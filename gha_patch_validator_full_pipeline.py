#!/usr/bin/env python3
"""
GHA Patch Validator full pipeline prototype.

Research scope of this prototype:
  S01 = issue title -> single-line run -> GitHub Actions script injection.

End-to-end pipeline implemented here:
  1. Deploy vulnerable workflow.
  2. Run CodeQL and locate the workflow-injection alert.
  3. PRE-PATCH dynamic validation:
       A) malicious input security run
       B) normal input functionality run
     Collect job conclusions, step outcomes, logs, and checkpoint markers.
  4. Generate candidate patch with Copilot Autofix, or use --manual-patch.
  5. Deploy generated candidate patch.
  6. Run CodeQL static recheck.
  7. POST-PATCH dynamic validation:
       A) malicious input security run
       B) normal input functionality run
     Collect the same checkpoints.
  8. Compare checkpoints and classify the patch.

The malicious input is harmless: it only tries to create a marker file under
$RUNNER_TEMP. It does not read secrets, publish packages, write to the repo, or
make network requests.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ROOT = Path.cwd()
API_VERSION = "2026-03-10"


class CommandError(RuntimeError):
    pass


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_z(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_github_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def run(cmd: List[str], *, check: bool = True, capture: bool = True, cwd: Path = ROOT) -> str:
    print("$", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode != 0:
        out = proc.stdout or ""
        err = proc.stderr or ""
        raise CommandError(f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return proc.stdout or ""


def gh_api_raw(args: List[str], *, check: bool = True) -> str:
    return run(["gh", "api", "-H", f"X-GitHub-Api-Version: {API_VERSION}"] + args, check=check)


def gh_api(repo: str, method: str, endpoint: str, fields: Optional[Dict[str, str]] = None, check: bool = True) -> Any:
    cmd = ["-X", method, f"repos/{repo}/{endpoint.lstrip('/')}"]
    if fields:
        for key, value in fields.items():
            cmd.extend(["-f", f"{key}={value}"])
    out = gh_api_raw(cmd, check=check)
    if not out.strip():
        return None
    return json.loads(out)


def git_has_changes() -> bool:
    return bool(run(["git", "status", "--porcelain"], check=True).strip())


def git_commit_push(message: str, branch: str = "main") -> None:
    run(["git", "add", "."], capture=True)
    if git_has_changes():
        run(["git", "commit", "-m", message], capture=False)
    else:
        print("No local changes to commit.")
    run(["git", "push", "origin", branch], capture=False)


def ensure_workflow_dir() -> Path:
    d = ROOT / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_oracle(sample_dir: Path) -> Dict[str, Any]:
    with (sample_dir / "oracle.yaml").open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def deploy_workflow(workflow_src: Path, workflow_file: str, message: str, branch: str = "main") -> Path:
    dst = ensure_workflow_dir() / workflow_file
    shutil.copyfile(workflow_src, dst)
    git_commit_push(message, branch=branch)
    return dst


def trigger_codeql(repo: str) -> None:
    # If repository uses CodeQL default setup, push events may already trigger analysis.
    # This workflow_dispatch is convenient for the prototype, but it is not required.
    run(["gh", "workflow", "run", "CodeQL GHA Scan", "--repo", repo], check=False)


def latest_run(repo: str, workflow: str, created_after: Optional[dt.datetime] = None) -> Optional[Dict[str, Any]]:
    out = run([
        "gh", "run", "list",
        "--repo", repo,
        "--workflow", workflow,
        "--limit", "30",
        "--json", "databaseId,status,conclusion,createdAt,displayTitle,event,headBranch,headSha,url",
    ], check=False)
    if not out.strip():
        return None
    runs = json.loads(out)
    if created_after:
        runs = [r for r in runs if parse_github_time(r["createdAt"]) >= created_after]
    if not runs:
        return None
    runs.sort(key=lambda r: parse_github_time(r["createdAt"]), reverse=True)
    return runs[0]


def wait_for_run(repo: str, workflow: str, created_after: dt.datetime, timeout_sec: int = 900) -> Dict[str, Any]:
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        r = latest_run(repo, workflow, created_after)
        if r:
            last = r
            print(f"Run {r['databaseId']} status={r['status']} conclusion={r.get('conclusion')}")
            if r["status"] == "completed":
                return r
        time.sleep(10)
    raise TimeoutError(f"Timed out waiting for workflow {workflow}. Last run: {last}")


def wait_for_codeql(repo: str, timeout_sec: int = 1200) -> Optional[Dict[str, Any]]:
    started = now_utc() - dt.timedelta(seconds=30)
    trigger_codeql(repo)
    try:
        return wait_for_run(repo, "CodeQL GHA Scan", started, timeout_sec=timeout_sec)
    except TimeoutError as e:
        print(f"WARNING: CodeQL workflow did not finish via workflow_dispatch: {e}")
        return None


def list_codeql_alerts(repo: str) -> List[Dict[str, Any]]:
    out = run([
        "gh", "api",
        "-H", f"X-GitHub-Api-Version: {API_VERSION}",
        f"repos/{repo}/code-scanning/alerts",
        "-f", "state=open",
        "-f", "tool_name=CodeQL",
        "-f", "per_page=100",
    ], check=False)
    if not out.strip():
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def find_target_alert(repo: str, rule_id: str, target_path: str, timeout_sec: int = 600) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        alerts = list_codeql_alerts(repo)
        for alert in alerts:
            rid = (alert.get("rule") or {}).get("id")
            loc = ((alert.get("most_recent_instance") or {}).get("location") or {})
            path = loc.get("path")
            if rid == rule_id and path == target_path:
                print(f"Found CodeQL alert: number={alert.get('number')} rule={rid} path={path}")
                return alert
        print(f"Waiting for CodeQL alert {rule_id} at {target_path}. Current open alerts: {len(alerts)}")
        time.sleep(15)
    return None


def get_run_jobs(repo: str, run_id: str) -> Dict[str, Any]:
    try:
        jobs = gh_api(repo, "GET", f"actions/runs/{run_id}/jobs?per_page=100")
        return jobs or {"jobs": []}
    except Exception as e:
        print(f"WARNING: Could not retrieve jobs for run {run_id}: {e}")
        return {"jobs": []}


def get_logs(repo: str, run_id: str) -> str:
    # `gh run view --log` internally handles the workflow log API. It is easier to
    # read than manually downloading and extracting the log zip.
    return run(["gh", "run", "view", run_id, "--repo", repo, "--log"], check=False)


def create_issue(repo: str, title: str, body: str) -> str:
    return run(["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body], check=True).strip()


def close_issue(repo: str, issue_url: str) -> None:
    run(["gh", "issue", "close", issue_url, "--repo", repo, "--comment", "Closing validator test issue."], check=False)


def run_issue_workflow_test(repo: str, workflow_file: str, issue_title: str, label: str) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    print(f"\n=== Dynamic test: {label} ===")
    started = now_utc() - dt.timedelta(seconds=10)
    issue_url = create_issue(repo, issue_title, f"GHA Patch Validator test: {label}\n\nCreated at {iso_z(started)}")
    print("Created issue:", issue_url)
    try:
        run_info = wait_for_run(repo, workflow_file, started, timeout_sec=900)
        run_id = str(run_info["databaseId"])
        logs = get_logs(repo, run_id)
        jobs = get_run_jobs(repo, run_id)
        return run_info, logs, jobs
    finally:
        close_issue(repo, issue_url)


def extract_step_outcomes(jobs_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for job in jobs_payload.get("jobs", []):
        for step in job.get("steps", []) or []:
            steps.append({
                "job_name": job.get("name"),
                "step_name": step.get("name"),
                "status": step.get("status"),
                "conclusion": step.get("conclusion"),
                "number": step.get("number"),
            })
    return steps


def build_checkpoint_record(oracle: Dict[str, Any], run_info: Dict[str, Any], logs: str, jobs_payload: Dict[str, Any], phase: str, test_type: str) -> Dict[str, Any]:
    sec = oracle["checkpoints"]["security"]
    func = oracle["checkpoints"]["functionality"]
    required = func["required_log_markers"]

    markers_found = {name: marker in logs for name, marker in required.items()}
    record = {
        "phase": phase,
        "test_type": test_type,
        "run_id": run_info.get("databaseId"),
        "run_url": run_info.get("url"),
        "event": run_info.get("event"),
        "created_at": run_info.get("createdAt"),
        "status": run_info.get("status"),
        "conclusion": run_info.get("conclusion"),
        "security_marker_present": sec["marker_present"] in logs,
        "security_marker_absent": sec["marker_absent"] in logs,
        "function_markers_found": markers_found,
        "function_markers_required": required,
        "step_outcomes": extract_step_outcomes(jobs_payload),
        "log_excerpt": select_log_excerpt(logs, [sec["marker_present"], sec["marker_absent"], *required.values()]),
    }
    return record


def select_log_excerpt(logs: str, markers: List[str], context_lines: int = 2) -> str:
    lines = logs.splitlines()
    selected: List[str] = []
    used_indexes = set()
    for i, line in enumerate(lines):
        if any(marker in line for marker in markers):
            for j in range(max(0, i - context_lines), min(len(lines), i + context_lines + 1)):
                if j not in used_indexes:
                    selected.append(lines[j])
                    used_indexes.add(j)
            selected.append("---")
    return "\n".join(selected[-120:])


def functionality_passed(record: Dict[str, Any], oracle: Dict[str, Any]) -> bool:
    expected = oracle["checkpoints"]["functionality"]["expected_conclusion"]
    return record["conclusion"] == expected and all(record["function_markers_found"].values())


def security_attack_triggered(record: Dict[str, Any]) -> bool:
    return bool(record["security_marker_present"])


def security_blocked(record: Dict[str, Any]) -> bool:
    return bool(record["security_marker_absent"]) and not bool(record["security_marker_present"])


def run_validation_suite(repo: str, oracle: Dict[str, Any], phase: str) -> Dict[str, Any]:
    workflow_file = oracle["workflow_file"]

    attack_run, attack_logs, attack_jobs = run_issue_workflow_test(
        repo,
        workflow_file,
        oracle["malicious_input"],
        f"{phase} security run: malicious issue title",
    )
    security_record = build_checkpoint_record(oracle, attack_run, attack_logs, attack_jobs, phase, "security_malicious")

    normal_run, normal_logs, normal_jobs = run_issue_workflow_test(
        repo,
        workflow_file,
        oracle["normal_input"],
        f"{phase} functionality run: normal issue title",
    )
    functionality_record = build_checkpoint_record(oracle, normal_run, normal_logs, normal_jobs, phase, "functionality_normal")

    return {
        "security_malicious": security_record,
        "functionality_normal": functionality_record,
    }


def create_copilot_autofix(repo: str, alert_number: int) -> Optional[Dict[str, Any]]:
    try:
        return gh_api(repo, "POST", f"code-scanning/alerts/{alert_number}/autofix")
    except CommandError as e:
        print("Copilot Autofix create request failed.")
        print(str(e))
        return None


def poll_copilot_autofix(repo: str, alert_number: int, timeout_sec: int = 900) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_sec
    last = None
    while time.time() < deadline:
        try:
            res = gh_api(repo, "GET", f"code-scanning/alerts/{alert_number}/autofix")
        except CommandError as e:
            print("Autofix status request failed:", e)
            return None
        last = res
        status = (res or {}).get("status")
        print(f"Autofix status={status}; description={(res or {}).get('description')}")
        if status == "success":
            return res
        if status in {"error", "failure", "failed"}:
            return res
        time.sleep(10)
    print("Timed out waiting for Copilot Autofix. Last response:", last)
    return last


def prepare_autofix_branch(branch: str) -> None:
    run(["git", "checkout", "main"], capture=False)
    run(["git", "pull", "--ff-only", "origin", "main"], capture=False)
    run(["git", "checkout", "-B", branch], capture=False)
    run(["git", "push", "-u", "origin", branch, "--force"], capture=False)
    run(["git", "checkout", "main"], capture=False)


def commit_autofix_to_branch(repo: str, alert_number: int, branch: str) -> Optional[Dict[str, Any]]:
    try:
        return gh_api(
            repo,
            "POST",
            f"code-scanning/alerts/{alert_number}/autofix/commits",
            fields={
                "target_ref": f"refs/heads/{branch}",
                "message": f"Apply Copilot Autofix for alert {alert_number}",
            },
        )
    except CommandError as e:
        print("Commit Autofix request failed.")
        print(str(e))
        return None


def extract_autofix_candidate(branch: str, workflow_file: str, output_path: Path) -> Path:
    run(["git", "fetch", "origin", branch], capture=False)
    run(["git", "checkout", branch], capture=False)
    run(["git", "pull", "--ff-only", "origin", branch], capture=False)
    src = ROOT / ".github" / "workflows" / workflow_file
    if not src.exists():
        run(["git", "checkout", "main"], capture=False)
        raise FileNotFoundError(f"Autofix branch does not contain {src}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, output_path)
    run(["git", "checkout", "main"], capture=False)
    return output_path


def generate_candidate_patch(repo: str, oracle: Dict[str, Any], alert: Optional[Dict[str, Any]], manual_patch: Optional[Path], branch_prefix: str) -> Tuple[Path, Optional[Dict[str, Any]]]:
    generated_patch = ROOT / "generated_patches" / f"copilot_autofix_{oracle['sample_id']}.yml"
    generated_patch.parent.mkdir(parents=True, exist_ok=True)

    if manual_patch:
        print(f"Using manual patch instead of Copilot Autofix: {manual_patch}")
        shutil.copyfile(manual_patch, generated_patch)
        return generated_patch, {"mode": "manual_patch", "source": str(manual_patch)}

    if alert is None:
        raise RuntimeError("No CodeQL alert available. Copilot Autofix cannot be requested automatically.")

    alert_number = int(alert["number"])
    branch = f"{branch_prefix}-{int(time.time())}"
    prepare_autofix_branch(branch)

    create_res = create_copilot_autofix(repo, alert_number)
    if create_res is None:
        raise RuntimeError("Copilot Autofix is unavailable for this alert/repository.")

    autofix_info = poll_copilot_autofix(repo, alert_number)
    if not autofix_info or autofix_info.get("status") != "success":
        raise RuntimeError("Copilot Autofix did not produce a successful suggestion.")

    commit_res = commit_autofix_to_branch(repo, alert_number, branch)
    if commit_res is None:
        raise RuntimeError("Copilot Autofix suggestion could not be committed to a branch.")

    extract_autofix_candidate(branch, oracle["workflow_file"], generated_patch)
    autofix_info["committed_branch"] = branch
    autofix_info["commit_response"] = commit_res
    return generated_patch, autofix_info


def classify_patch(oracle: Dict[str, Any], pre: Dict[str, Any], post: Dict[str, Any], patched_static_alert_open: Optional[bool]) -> Dict[str, Any]:
    pre_sec = pre["security_malicious"]
    pre_func = pre["functionality_normal"]
    post_sec = post["security_malicious"]
    post_func = post["functionality_normal"]

    baseline_security_ok = security_attack_triggered(pre_sec)
    baseline_functionality_ok = functionality_passed(pre_func, oracle)
    patched_security_ok = security_blocked(post_sec)
    patched_functionality_ok = functionality_passed(post_func, oracle)
    patched_normal_success = post_func["conclusion"] == oracle["checkpoints"]["functionality"]["expected_conclusion"]

    comparison = {
        "baseline_security_attack_triggered": baseline_security_ok,
        "baseline_functionality_passed": baseline_functionality_ok,
        "patched_security_blocked": patched_security_ok,
        "patched_normal_success": patched_normal_success,
        "patched_functionality_passed": patched_functionality_ok,
        "patched_static_alert_open": patched_static_alert_open,
        "functionality_checkpoint_diff": {},
    }

    for name in pre_func["function_markers_found"]:
        comparison["functionality_checkpoint_diff"][name] = {
            "pre_patch": pre_func["function_markers_found"].get(name),
            "post_patch": post_func["function_markers_found"].get(name),
        }

    if not baseline_security_ok or not baseline_functionality_ok:
        classification = "Invalid-Benchmark"
        reason = "The vulnerable baseline did not satisfy the expected exploitable/security or normal-functionality baseline."
    elif not patched_security_ok:
        classification = "Reject-Security"
        reason = "The post-patch malicious-input run still indicates command execution or did not show marker absence."
    elif not patched_normal_success:
        classification = "Invalid"
        reason = "The patched workflow did not complete successfully under normal input."
    elif not patched_functionality_ok:
        classification = "Reject-Functionality"
        reason = "The patched workflow ran but failed one or more local observable functionality checkpoints."
    else:
        classification = "Accept"
        reason = "The patch blocks the malicious marker and preserves the normal-input functionality checkpoints."

    return {
        "classification": classification,
        "reason": reason,
        "comparison": comparison,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="GHA Patch Validator full pipeline with pre/post checkpoint comparison")
    parser.add_argument("--repo", required=True, help="GitHub repository, e.g. OWNER/REPO")
    parser.add_argument("--sample", required=True, type=Path, help="Sample directory")
    parser.add_argument("--branch-prefix", default="autofix-s01", help="Branch prefix for Copilot Autofix commit")
    parser.add_argument("--manual-patch", type=Path, help="Use this patch file instead of calling Copilot Autofix")
    parser.add_argument("--skip-codeql-wait", action="store_true", help="Skip CodeQL run/alert wait. Requires --manual-patch.")
    args = parser.parse_args()

    if args.skip_codeql_wait and not args.manual_patch:
        print("--skip-codeql-wait can only be used with --manual-patch, because Copilot Autofix requires a CodeQL alert.", file=sys.stderr)
        return 2

    sample_dir = args.sample
    oracle = load_oracle(sample_dir)
    workflow_file = oracle["workflow_file"]
    rule_id = oracle["codeql"]["expected_rule_id"]
    target_path = oracle["codeql"]["target_path"]

    report: Dict[str, Any] = {
        "sample_id": oracle["sample_id"],
        "created_at": iso_z(now_utc()),
        "pipeline": "CodeQL -> pre-patch security/functionality -> Copilot Autofix -> post-patch security/functionality -> classification",
        "repo": args.repo,
        "workflow_file": workflow_file,
    }

    # 1. Deploy vulnerable workflow.
    vulnerable_path = sample_dir / "vulnerable.yml"
    deploy_workflow(vulnerable_path, workflow_file, "deploy vulnerable S01 workflow for baseline validation")

    # 2. Run CodeQL and locate alert for Copilot Autofix.
    alert = None
    if not args.skip_codeql_wait:
        wait_for_codeql(args.repo)
        alert = find_target_alert(args.repo, rule_id, target_path)
        if alert is None and not args.manual_patch:
            raise RuntimeError("Could not find the target CodeQL alert. Cannot request Copilot Autofix automatically.")
    report["codeql_alert_before_patch"] = alert

    # 3. PRE-PATCH dynamic validation: malicious + normal.
    print("\n############################")
    print("# PRE-PATCH VALIDATION")
    print("############################")
    pre = run_validation_suite(args.repo, oracle, "pre_patch")
    report["pre_patch"] = pre

    # 4. Generate candidate patch using Copilot Autofix, unless manual-patch is provided.
    generated_patch, autofix_info = generate_candidate_patch(args.repo, oracle, alert, args.manual_patch, args.branch_prefix)
    report["candidate_patch"] = {
        "path": str(generated_patch),
        "generation": autofix_info,
    }

    # 5. Deploy candidate patch.
    deploy_workflow(generated_patch, workflow_file, "deploy candidate patch for post-patch validation")

    # 6. Static recheck after patch.
    patched_static_alert_open: Optional[bool] = None
    if not args.skip_codeql_wait:
        wait_for_codeql(args.repo)
        patched_alert = find_target_alert(args.repo, rule_id, target_path, timeout_sec=90)
        patched_static_alert_open = patched_alert is not None
        report["codeql_alert_after_patch"] = patched_alert
    else:
        report["codeql_alert_after_patch"] = None

    # 7. POST-PATCH dynamic validation: malicious + normal.
    print("\n############################")
    print("# POST-PATCH VALIDATION")
    print("############################")
    post = run_validation_suite(args.repo, oracle, "post_patch")
    report["post_patch"] = post

    # 8. Classify.
    classification = classify_patch(oracle, pre, post, patched_static_alert_open)
    report["classification_result"] = classification

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{oracle['sample_id']}_full_pipeline_report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== FINAL CLASSIFICATION ===")
    print(json.dumps(classification, ensure_ascii=False, indent=2))
    print("\nFull report saved to", out_path)
    print("Patch candidate saved to", generated_patch)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CommandError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)

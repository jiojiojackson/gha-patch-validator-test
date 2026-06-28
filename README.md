# GHA Patch Validator Full Pipeline Prototype

This prototype implements the corrected research flow for the first dataset sample:

> S01 = `issue title` → `single-line run` → GitHub Actions shell script injection.

The full pipeline is:

```text
CodeQL detection
→ pre-patch malicious-input security validation
→ pre-patch normal-input functionality validation
→ Copilot Autofix candidate patch generation
→ post-patch malicious-input security validation
→ post-patch normal-input functionality validation
→ checkpoint comparison
→ patch classification
```

The key difference from a simpler validator is that the vulnerable workflow is also executed before patching with both malicious and normal inputs. This creates a baseline:

- baseline security: the vulnerable workflow is actually exploitable;
- baseline functionality: the vulnerable workflow has the expected local observable behavior under normal input.

Only after these two baseline checks pass does the patch classification become meaningful.

---

## Directory structure

```text
gha_patch_validator_full_pipeline_prototype/
├── .github/workflows/codeql.yml
├── gha_patch_validator_full_pipeline.py
├── requirements.txt
├── generated_patches/
├── results/
└── samples/s01_issue_title_single_run/
    ├── oracle.yaml
    ├── vulnerable.yml
    └── patches/
        ├── patched_env.yml
        ├── bad_patch_still_direct.yml
        └── bad_patch_breaks_functionality.yml
```

---

## Dataset sample: S01

### Source

```yaml
${{ github.event.issue.title }}
```

### Sink

```yaml
run: title="${{ github.event.issue.title }}"; echo "VALUE::$title"
```

### Normal input

```text
Release v1.0
```

### Harmless malicious input

```text
Release v1.0"; echo "marker" > "$RUNNER_TEMP/gha_validator_s01_marker"; #
```

The payload only creates a marker file inside the temporary runner directory. It does not read secrets, does not contact the network, does not write to the repository, and does not publish anything.

---

## Checkpoints collected in every dynamic run

Each workflow version is executed twice:

| Phase | Input | Purpose |
|---|---|---|
| pre_patch | malicious issue title | Confirm the vulnerable benchmark is exploitable |
| pre_patch | normal issue title | Establish baseline functionality |
| post_patch | malicious issue title | Check whether patch blocks injected command execution |
| post_patch | normal issue title | Check whether patch preserves baseline local behavior |

For each run, the validator records:

```text
run_id
run_url
run conclusion
security_marker_present
security_marker_absent
function checkpoint: VALUE::Release v1.0
function checkpoint: DOWNSTREAM_REACHED
step outcomes from GitHub Actions jobs API
selected log excerpts around checkpoint markers
```

---

## Classification logic

```text
if pre_patch malicious run does not show EXECUTION_MARKER_PRESENT:
    Invalid-Benchmark

if pre_patch normal run does not pass all functionality checkpoints:
    Invalid-Benchmark

if post_patch malicious run still shows EXECUTION_MARKER_PRESENT:
    Reject-Security

if post_patch normal run does not complete successfully:
    Invalid

if post_patch normal run completes but misses VALUE::Release v1.0 or DOWNSTREAM_REACHED:
    Reject-Functionality

otherwise:
    Accept
```

Static CodeQL recheck after patch is recorded in the report, but the final classification is based on the dynamic security and functionality checkpoints. This is intentional because the research question compares static alert disappearance with dynamic validation results.

---

## Prerequisites

Install:

- Git
- Python 3.10+
- GitHub CLI (`gh`)
- PowerPoint is not needed for this prototype

Authenticate with GitHub CLI:

```bash
gh auth login
gh auth status
```

For the Copilot Autofix part, the repository must support CodeQL code scanning and Copilot Autofix for code scanning. Public repositories on GitHub.com are the easiest setting to test.

---

## Deployment steps

### 1. Create a test repository

```bash
gh repo create gha-patch-validator-test --public --clone
cd gha-patch-validator-test
```

### 2. Copy the prototype into the repository

From the unpacked ZIP directory:

```bash
cp -R /path/to/gha_patch_validator_full_pipeline_prototype/* .
cp -R /path/to/gha_patch_validator_full_pipeline_prototype/.github .
```

### 3. Commit and push

```bash
git add .
git commit -m "add full GHA patch validator prototype"
git push -u origin main
```

### 4. Install Python dependency

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

---

## Run the full Copilot Autofix pipeline

```bash
python gha_patch_validator_full_pipeline.py \
  --repo OWNER/REPO \
  --sample samples/s01_issue_title_single_run
```

Example:

```bash
python gha_patch_validator_full_pipeline.py \
  --repo yourname/gha-patch-validator-test \
  --sample samples/s01_issue_title_single_run
```

The script will:

```text
1. Deploy samples/s01_issue_title_single_run/vulnerable.yml as .github/workflows/s01_under_test.yml
2. Run CodeQL and find actions/code-injection/medium
3. Run pre-patch malicious validation
4. Run pre-patch normal functionality validation
5. Ask Copilot Autofix to generate a candidate patch
6. Commit the Autofix patch to an autofix-* branch
7. Extract the patched workflow into generated_patches/
8. Deploy the patched workflow to main
9. Run CodeQL static recheck
10. Run post-patch malicious validation
11. Run post-patch normal functionality validation
12. Compare checkpoints and classify the patch
```

---

## Manual-patch mode for local testing

If Copilot Autofix is unavailable because of repository settings, you can still test the full pre/post validation logic with a prepared patch.

### Expected Accept

```bash
python gha_patch_validator_full_pipeline.py \
  --repo OWNER/REPO \
  --sample samples/s01_issue_title_single_run \
  --manual-patch samples/s01_issue_title_single_run/patches/patched_env.yml \
  --skip-codeql-wait
```

### Expected Reject-Security

```bash
python gha_patch_validator_full_pipeline.py \
  --repo OWNER/REPO \
  --sample samples/s01_issue_title_single_run \
  --manual-patch samples/s01_issue_title_single_run/patches/bad_patch_still_direct.yml \
  --skip-codeql-wait
```

### Expected Reject-Functionality

```bash
python gha_patch_validator_full_pipeline.py \
  --repo OWNER/REPO \
  --sample samples/s01_issue_title_single_run \
  --manual-patch samples/s01_issue_title_single_run/patches/bad_patch_breaks_functionality.yml \
  --skip-codeql-wait
```

---

## Output

The main report is saved to:

```text
results/s01_issue_title_single_run_full_pipeline_report.json
```

The generated candidate patch is saved to:

```text
generated_patches/copilot_autofix_s01_issue_title_single_run.yml
```

The JSON report contains:

```json
{
  "pre_patch": {
    "security_malicious": { "...": "..." },
    "functionality_normal": { "...": "..." }
  },
  "post_patch": {
    "security_malicious": { "...": "..." },
    "functionality_normal": { "...": "..." }
  },
  "classification_result": {
    "classification": "Accept | Reject-Security | Reject-Functionality | Invalid | Invalid-Benchmark",
    "comparison": {
      "baseline_security_attack_triggered": true,
      "baseline_functionality_passed": true,
      "patched_security_blocked": true,
      "patched_functionality_passed": true
    }
  }
}
```

---

## Research interpretation

This prototype supports the revised research design:

1. The vulnerable sample is not assumed to be exploitable; it is first dynamically confirmed.
2. The vulnerable sample's normal behavior is not assumed; it is recorded as a baseline.
3. The candidate patch is not judged only by static alert disappearance.
4. The final classification is based on before/after checkpoint comparison.
5. Functionality preservation is limited to local observable checkpoints rather than full semantic equivalence.

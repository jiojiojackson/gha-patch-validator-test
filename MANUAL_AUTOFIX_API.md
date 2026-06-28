# Copilot Autofix API notes

The script calls the Code Scanning Autofix REST API through GitHub CLI.

## Create or request an autofix

```bash
gh api \
  -X POST \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/OWNER/REPO/code-scanning/alerts/ALERT_NUMBER/autofix
```

## Poll autofix status

```bash
gh api \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/OWNER/REPO/code-scanning/alerts/ALERT_NUMBER/autofix
```

## Commit autofix to a branch

```bash
gh api \
  -X POST \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  repos/OWNER/REPO/code-scanning/alerts/ALERT_NUMBER/autofix/commits \
  -f target_ref=refs/heads/autofix-s01 \
  -f message='Apply Copilot Autofix for S01'
```

After committing, the validator checks out the autofix branch and extracts:

```text
.github/workflows/s01_under_test.yml
```

This file becomes the generated candidate patch and is then validated dynamically.

# Restore failed — why and how to finish in 1 minute

## Why Restore failed

The restore **job succeeded** (file built, YAML valid, uro/asnmap fixes applied).

Push failed with:

```
refusing to allow a GitHub App to create or update workflow
`.github/workflows/zero-track-hunter.yml` without `workflows` permission
```

`GITHUB_TOKEN` in Actions **cannot** modify workflow files unless the token has the `workflows` permission (GitHub security restriction).

## Fix (pick one)

### Option A — Web UI (fastest)
1. Open: https://github.com/Tawffik/BugBountyCI/edit/main/.github/workflows/zero-track-hunter.yml
2. Delete all content in the editor
3. Paste content from the file Grok gave you: `zero-track-hunter.FIXED.yml`
4. Commit to `main`

### Option B — PAT with workflow scope
1. Create a classic PAT with scopes: `repo` + `workflow`
2. Repo Settings → Secrets → `WORKFLOW_PAT`
3. Re-run Restore after we update it to use that secret

### Option C — local git
```bash
git clone https://github.com/Tawffik/BugBountyCI.git
cd BugBountyCI
# put zero-track-hunter.FIXED.yml as .github/workflows/zero-track-hunter.yml
git add .github/workflows/zero-track-hunter.yml
git commit -m "fix(pipeline): restore full workflow + uro/asnmap/classify"
git push
```

After restore, run **Zero Track** normally and check `urls/all.txt` > 0.

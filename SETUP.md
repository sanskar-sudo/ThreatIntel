# Threat Actor Intelligence Dashboard — Setup Guide

Live MITRE ATT&CK data, auto-updated every Monday via GitHub Actions. Zero cost, zero maintenance after setup.

---

## What you are setting up

```
Your GitHub Repo
├── threat-actors.html        The dashboard (served by GitHub Pages)
├── package.json              Node.js dependencies for the update script
├── scripts/
│   └── fetch-attack-data.js  Fetches MITRE data and rewrites the HTML
└── .github/
    └── workflows/
        └── update-attack-data.yml  Runs every Monday automatically
```

Every Monday at 9am UTC, GitHub Actions:
1. Spins up a Node.js environment (free, ~2 min of your 2000 free minutes/month)
2. Fetches the latest MITRE ATT&CK STIX dataset from GitHub
3. Parses all groups, techniques, software, and campaigns
4. Rewrites the DATA block inside threat-actors.html
5. Commits and pushes the updated file
6. GitHub Pages redeploys automatically

The "Last updated" badge in the top bar always reflects the date of the last run.

---

## Step 1 — File structure

Add all four files to your repo so the structure looks exactly like this:

```
ThreatAPI/
├── index.html
├── threat-actors.html          <-- download from Claude
├── package.json                <-- download from Claude
├── scripts/
│   └── fetch-attack-data.js    <-- download from Claude
└── .github/
    └── workflows/
        └── update-attack-data.yml   <-- download from Claude
```

Important notes:
- The `.github` folder name starts with a dot. Make sure it is not renamed.
- The `workflows` folder must be inside `.github`, not at the root.
- The folder names must be exact — GitHub only looks in `.github/workflows/`.

---

## Step 2 — Create the folders and commit

Open a terminal in your repo folder and run:

```bash
# Create the required folders
mkdir -p .github/workflows
mkdir -p scripts

# Copy the files you downloaded into the right places
# (do this manually in File Explorer or with cp commands)

# Then commit everything
git add .
git commit -m "add threat actor dashboard with auto-update workflow"
git push origin main
```

On Windows, creating a folder starting with a dot can be tricky in File Explorer.
Use the terminal instead:

```bash
mkdir .github
mkdir .github\workflows
mkdir scripts
```

---

## Step 3 — Verify the workflow appears on GitHub

1. Go to your repo on github.com
2. Click the **Actions** tab at the top of the page
3. You should see **Update MITRE ATT&CK Data** listed in the left sidebar

If you do not see it, the `.github/workflows/` folder structure is wrong. Double-check the folder names.

---

## Step 4 — Run it manually to test

Do not wait until Monday. Trigger it now:

1. Click **Actions** tab on GitHub
2. Click **Update MITRE ATT&CK Data** in the left sidebar
3. Click the **Run workflow** dropdown on the right side
4. Click the green **Run workflow** button
5. Refresh the page — a new run appears with a yellow dot (running)
6. Click on it to watch the live logs
7. The whole run takes about 60 seconds

When it finishes (green checkmark), go to your repo's main **Code** tab. You will see a new commit at the top:

```
chore: update MITRE ATT&CK data 2025-03-23
```

Your GitHub Pages site will redeploy within 30 seconds after that commit.

---

## Step 5 — Visit your live site

Open your GitHub Pages URL:

```
https://your-username.github.io/ThreatAPI/threat-actors.html
```

You will see:
- The "Last updated: 2025-03-23" badge in the top right
- All threat actor data freshly pulled from MITRE ATT&CK

---

## After setup — nothing to do

The workflow runs automatically every Monday at 9am UTC. You will see a new commit every week. The badge updates automatically. No manual steps required.

If MITRE releases a new ATT&CK version, the script picks it up on the next Monday run. If you want to update the STIX URL to a newer version (e.g., v17 when it releases), edit line 10 of `scripts/fetch-attack-data.js`:

```js
const STIX_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json';
```

Change `enterprise-attack-16.1.json` to whatever the latest version is.

---

## Troubleshooting

**Actions tab shows no workflow**
The `.github/workflows/` folder structure is wrong. Check that `.github` starts with a dot and `workflows` is spelled correctly.

**Workflow fails with "not found" error**
The `threat-actors.html` file does not contain the `ATTACK_DATA_START` and `ATTACK_DATA_END` markers. Make sure you are using the version of `threat-actors.html` downloaded from Claude, not an older version.

**Workflow fails with "permission denied" on git push**
Go to your repo Settings, then Actions, then General. Scroll to Workflow permissions and select "Read and write permissions". Save.

**Badge shows old date**
The workflow ran but something in the commit step failed. Check the Actions log for the specific error.

---

## Cost summary

| Service | Usage | Cost |
|---|---|---|
| GitHub Actions | ~10 min/month | Free (2000 min/month included) |
| GitHub Pages | Static hosting | Free |
| MITRE ATT&CK data | Public dataset | Free |
| Total | | $0 |

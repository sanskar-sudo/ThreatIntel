# ThreatIntel

A threat actor intelligence dashboard built on real MITRE ATT&CK data. Browse 100+ tracked threat groups, techniques, malware, and attack campaigns in a clean single-file interface. Data updates automatically every Monday via GitHub Actions.

**Live at: https://sanskar-sudo.github.io/ThreatIntel/**

---
<img width="1908" height="947" alt="image" src="https://github.com/user-attachments/assets/f8ed1dc2-4680-44c3-a9ab-d89003fc55de" />

## Features

**Threat Actors** - 100+ real APT groups with origin countries, aliases, technique counts, and full descriptions. Search by name, filter by origin, sort by activity.

**Techniques** - MITRE ATT&CK techniques grouped by tactic. Each card shows which threat actors use it and links to the official MITRE page.

**Coverage Map** - Heatmap of every actor versus every tactic. Color intensity reflects how many techniques each actor uses per tactic. Click any cell to drill into that actor's details.

**Malware and Tools** - Every malware family and tool in the ATT&CK dataset with type badges, aliases, and descriptions.

**Actor Detail Panel** - Slides in from the right with four tabs: Overview, Techniques, Software, and Campaigns.

---

## Auto-update

A GitHub Actions workflow runs every Monday at 9am UTC. It fetches the latest MITRE ATT&CK STIX dataset, parses all objects, rewrites the data block inside `threat-actors.html`, and commits the result. The "Last updated" badge in the top bar reflects the date of the last run.

No manual steps required after initial setup.

---

## Tech stack

Pure HTML, CSS, and vanilla JavaScript. No frameworks, no build step, no runtime dependencies. The only network request is the Google Fonts import. Data is embedded directly in the HTML file.

The update script is Node.js and runs only inside GitHub Actions.

---

## Repo structure

```
ThreatIntel/
├── index.html                         Redirects to threat-actors.html
├── threat-actors.html                 The dashboard
├── package.json                       Node.js deps for the update script
├── scripts/
│   └── fetch-attack-data.js           Fetches and parses MITRE STIX data
└── .github/
    └── workflows/
        └── update-attack-data.yml     Weekly automation schedule
```

---

## Setup

See `SETUP.md` for full step-by-step instructions including how to enable GitHub Pages and trigger a manual update run.

---

## Data source

[MITRE ATT&CK](https://attack.mitre.org) by The MITRE Corporation, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

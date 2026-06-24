# nerdio

A personal library of PowerShell scripted actions and tools for [Nerdio Manager for Enterprise (NME)](https://getnerdio.com/nerdio-manager-for-enterprise/).

Scripts are organised by **function** (what they do), then by **execution type** (how NME runs them).

## Structure

```
scripted-actions/
├── avd/
│   ├── windows/    # In-guest scripts run via NME agent
│   └── runbook/    # Azure Automation Runbook scripts
├── compliance/
│   ├── windows/
│   └── runbook/
├── cost/
│   ├── windows/
│   └── runbook/
└── lab/
    ├── windows/
    └── runbook/
```

## Usage

Each script includes an NME-compatible variable block at the top. Copy the script content directly into NME as a new Scripted Action, or reference this repo via NME's GitHub integration.

## Related

- [getnerdio/nerdio-actions](https://github.com/getnerdio/nerdio-actions) — Official Nerdio scripted actions library
- [aaronparker/nerdio](https://github.com/aaronparker/nerdio) — Community scripts by Aaron Parker

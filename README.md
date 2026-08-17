# DLV Feature

DLV Feature is a Codex skill for delivering a feature through one evidence-backed chain:

```text
Requirement Review → PRD ↔ Prototype (optional) → Architecture → Code Spec → Code → Verification
```

It keeps product behavior, technical decisions, implementation scope, and verification evidence separate. The workflow enforces truth, context, simplicity, boundary-proof, and evidence-integrity gates.

## Install

Add the marketplace from this repository, then install the plugin:

```bash
codex plugin marketplace add https://github.com/lessYFF/dlv-feature
codex plugin add dlv-feature@dlv-feature-marketplace
```

Start a new Codex thread after installation, then ask Codex to deliver a feature end to end. The skill is selected when the request matches feature development, implementation, delivery, or resumption work.

## Contents

- `plugins/dlv-feature/skills/dlv-feature/` — the skill, workflow guides, validation scripts, and Codex metadata.
- `.agents/plugins/marketplace.json` — marketplace entry for the plugin.

## License

No license has been selected yet. All rights are reserved unless the repository owner adds one.

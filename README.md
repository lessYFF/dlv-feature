# DLV Feature

Current plugin version: **0.4.0** (schema v8).

DLV Feature is a Codex skill for delivering a feature through one proof-carrying chain:

```text
Requirement Approval → PRD ↔ Prototype Product Approval → Architecture Quality Review + Human Approval → Code Spec Quality Review + Human Approval → Sealed Proof Contract → Code → Verification → Deterministic Finalization
```

It keeps product behavior, approved visual intent, technical decisions, implementation scope, and verification evidence separate. Schema v8 adds fingerprint-bound approval receipts, independent Architecture and Code Spec quality reviews, schema-focused commented SQL, typed visual/runtime evidence, a report from Verification start, and an explicit final validation mode. A document, build, or agent can no longer self-award `completed`.

Existing schema-v7 deliveries require a conservative review before resuming:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root>
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root> --apply
```

The first command is a dry run. The applied upgrade preserves documents, raw evidence, and the Proof Contract draft's ENV/PO/ASRT definitions, but invalidates all v7 approvals, quality verdicts, seals, PASS, and finalization. V8 requires fresh human confirmation and verification.

## Install from this repository marketplace

This repository contains a **repo marketplace**, not a public-directory
listing. It is discoverable after you add this marketplace and then select
`DLV Feature Marketplace` as the source; it is not indexed by the universal
Plugins Directory search until it is submitted and approved for public
publication.

Add the marketplace, then install the plugin:

```bash
codex plugin marketplace add lessYFF/dlv-feature --ref main
codex plugin add dlv-feature@dlv-feature-marketplace
```

Verify that Codex can resolve the marketplace and plugin:

```bash
codex plugin marketplace list
codex plugin list
```

For the ChatGPT desktop app, open the repository as a workspace, restart the
app, then open the Plugins Directory and choose `DLV Feature Marketplace` as
the marketplace source. Search or browse there for `DLV Feature`.

Start a new Codex thread after installation, then ask Codex to deliver a
feature end to end. The skill is selected when the request matches feature
development, implementation, delivery, or resumption work.

## Publish to the universal Plugins Directory

Adding `marketplace.json` only supports local, repository, and team
distribution. To make this plugin searchable in the universal directory shared
by ChatGPT and Codex, submit the skills-only plugin through the [OpenAI plugin
submission portal](https://platform.openai.com/plugins). The submitting
organization needs Apps Management write access and a verified developer or
business identity; after review approval, publish the plugin from the portal.

Before submitting, prepare the public listing details (website, support,
privacy policy, terms, logo), starter prompts, and at least five positive plus
three negative test cases. These are publication requirements rather than
fields that a repository marketplace can supply.

## Contents

- `plugins/dlv-feature/skills/dlv-feature/` — the skill, workflow guides, validation scripts, and Codex metadata.
- `.agents/plugins/marketplace.json` — marketplace entry for the plugin.

## License

No license has been selected yet. All rights are reserved unless the repository owner adds one.

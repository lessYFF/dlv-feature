# DLV Feature

Current plugin version: **0.5.0** (delivery schema v9).

DLV Feature is a Codex skill for delivering a feature through one proof-carrying chain:

```text
Requirements + PRD + Prototype → Product Contract Review → Architecture Risk Review → Code Spec Coverage Review → Sealed Proof Contract → Code → Verification → Deterministic Finalization
```

It keeps product behavior, visual intent, technical decisions, implementation scope, and verification evidence separate. Schema v9 has zero routine human confirmation gates. Instead, three immutable automated reviews bind the exact input hashes and block progression on missing required checks, less than 100% required coverage, unmapped changes, or open critical/major findings:

- Product Contract Review jointly checks source requirements, PRD, and Prototype or the explicit no-prototype decision.
- Architecture Risk Review checks database change, API compatibility, existing-business impact, authorization/tenant boundaries, and fact ownership.
- Code Spec Coverage Review checks complete PRD, Prototype, risk, and proof coverage with zero unmapped changes.

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py product <feature-id> \
  --root <project-root> --run-id <run-id>
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py architecture <feature-id> \
  --root <project-root> --run-id <run-id>
python3 plugins/dlv-feature/skills/dlv-feature/scripts/quality_review.py code_spec <feature-id> \
  --root <project-root> --run-id <run-id>
```

Each command launches its own ephemeral, read-only `codex exec` reviewer. The runner owns the verdict input, invocation identity, transcript, and transcript hash; callers cannot submit a prebuilt PASS result.

An artifact or bound input change invalidates its review and every downstream claim. Genuine unresolved requirement ambiguity may still block for clarification. Authorization for external mutations remains governed by the host and repository policy; it is not a routine delivery confirmation.

Existing schema-v8 deliveries require a conservative upgrade before resuming:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v8_to_v9.py <feature-id> --root <project-root>
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v8_to_v9.py <feature-id> --root <project-root> --apply
```

The first command is a dry run. The applied upgrade preserves documents, code, and raw evidence only as untrusted candidates; it removes legacy approval state and invalidates every old quality verdict, seal, PASS, and finalization. Three fresh automated reviews and a fresh Verification Run are required.

Schema-v7 deliveries first use the existing v7-to-v8 migration, then v8-to-v9:

```bash
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root>
python3 plugins/dlv-feature/skills/dlv-feature/scripts/upgrade_v7_to_v8.py <feature-id> --root <project-root> --apply
```

After applying v7-to-v8, run the v8-to-v9 commands above. No prior review or completion claim crosses either migration boundary.

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

#!/usr/bin/env python3
"""Domain obligations on existing Risk nodes; no second editable contract."""

from __future__ import annotations

from typing import Any

DOMAIN_AXES = {
    "database": {"PERSISTENCE"},
    "compatibility": {"API_CONTRACT", "CROSS_CLIENT"},
    "authorization": {"AUTHORIZATION", "TENANCY"},
    "money": {"MONEY"},
    "concurrency": {"CONCURRENCY"},
}


def domains_for(axes: set[str]) -> set[str]:
    return {domain for domain, triggers in DOMAIN_AXES.items() if triggers & axes}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _texts(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_text(item) for item in value)


def domain_roles(domain: str, context: Any, axes: set[str]) -> tuple[set[str], list[str]]:
    """Return required measured roles and context errors, never a PASS waiver."""
    if not isinstance(context, dict):
        return set(), ["context must be an object"]
    errors: list[str] = []

    def text_fields(*fields: str) -> None:
        errors.extend(f"context.{field} must be concrete" for field in fields if not _text(context.get(field)))

    if domain == "database":
        roles = {"data_preservation"}
        text_fields("engine", "engine_version")
        kind = context.get("change_kind")
        if kind not in ("data", "schema", "destructive_schema"):
            errors.append("context.change_kind must be data, schema or destructive_schema")
        if kind in ("schema", "destructive_schema"):
            text_fields("from_schema", "to_schema", "rollback_boundary")
            if not _texts(context.get("consumers")):
                errors.append("context.consumers must list supported database consumers")
            roles |= {"legacy_io", "migration_recovery"}
        if kind == "destructive_schema":
            text_fields("recovery_method", "destructive_execution_conditions")
            roles |= {"consumer_retirement", "recovery_readback"}
    elif domain == "compatibility":
        roles = {"legacy_workflow", "legacy_readback"}
        if not _texts(context.get("supported_clients")):
            errors.append("context.supported_clients must define the support range")
        text_fields("historical_state", "rollout_order")
        if context.get("reverse_combination") == "required":
            roles.add("reverse_workflow")
        elif context.get("reverse_combination") == "unreachable":
            text_fields("reverse_reason")
        else:
            errors.append("context.reverse_combination must be required or unreachable")
    elif domain == "authorization":
        roles = {"allowed_access", "denied_access", "denied_side_effects", "revoked_session", "revocation_window"}
        text_fields("principal_scope", "resource_scope")
        seconds = context.get("revocation_max_seconds")
        if type(seconds) is not int or seconds < 0:
            errors.append("context.revocation_max_seconds must be a nonnegative integer")
        if "TENANCY" in axes:
            roles.add("tenant_isolation")
    elif domain == "money":
        roles = {"amount_invariant", "side_effect_count"}
        text_fields("currency", "unit", "business_key")
    else:
        roles = {"interleaving", "invariant_readback"}
        text_fields("schedule", "failure_point")
    return roles, errors


def high_risk_issues(graph: dict[str, Any], required_risk: dict[str, str] | None = None) -> list[dict[str, str]]:
    nodes = {node["id"]: node for node in graph.get("nodes", []) if isinstance(node, dict) and "id" in node}
    edges = graph.get("edges", [])
    issues: list[dict[str, str]] = []

    def add(node_id: str, code: str, message: str) -> None:
        issues.append({"node_id": node_id, "code": code, "statement": message, "severity": "critical"})

    declared = graph.get("metadata", {}).get("risk_vector", {})
    required_axes = {axis for axis, level in {**declared}.items() if level != "absent"}
    required_axes |= {axis for axis, level in (required_risk or {}).items() if level != "absent"}
    risks = [node for node in nodes.values() if node.get("type") == "Risk"]
    risk_axes = {}
    for risk in risks:
        axes = risk.get("attributes", {}).get("risk_axes", [])
        if not _texts(axes):
            add(risk["id"], "HIGH_RISK_AXES_INVALID", "Risk.risk_axes must be a nonempty array of risk axis names")
            risk_axes[risk["id"]] = set()
        else:
            risk_axes[risk["id"]] = set(axes)
    modeled_axes = set().union(*risk_axes.values())
    modeled = domains_for(modeled_axes)
    for domain in sorted(domains_for(required_axes) - modeled):
        add("GRAPH", "HIGH_RISK_UNMODELED", f"{domain} risk requires a Risk with domain verification obligations")
    recognized_axes = set().union(*DOMAIN_AXES.values())
    for axis in sorted((required_axes & recognized_axes) - modeled_axes):
        if domains_for({axis}) <= modeled:
            add("GRAPH", "HIGH_RISK_UNMODELED", f"{axis} requires an explicitly modeled Risk axis; a related domain cannot substitute for it")
    for risk in risks:
        attrs = risk.get("attributes", {})
        axes = risk_axes[risk["id"]]
        required = domains_for(axes)
        if not required:
            continue
        verification = attrs.get("verification")
        if not isinstance(verification, dict) or set(verification) != {"symbols", "domains"}:
            add(risk["id"], "HIGH_RISK_CONTRACT_MISSING", "Risk requires verification={symbols, domains}")
            continue
        symbols = verification["symbols"]
        if not _texts(symbols) or any(nodes.get(item, {}).get("type") != "Symbol" for item in symbols):
            add(risk["id"], "HIGH_RISK_SYMBOLS_INVALID", "verification.symbols must reference concrete implementation Symbols")
        else:
            changes = {edge["source"] for edge in edges if edge.get("type") == "mitigates" and edge.get("target") == risk["id"] and nodes.get(edge.get("source"), {}).get("type") == "Change"}
            affected = {edge["source"] for edge in edges if edge.get("type") == "depends_on" and edge.get("target") in changes and nodes.get(edge.get("source"), {}).get("type") == "Symbol"}
            if not affected or not affected <= set(symbols):
                add(risk["id"], "HIGH_RISK_SYMBOLS_UNCOVERED", "verification must include every Symbol of the mitigating Changes")
        domains = verification["domains"]
        if not isinstance(domains, dict) or set(domains) != required:
            add(risk["id"], "HIGH_RISK_DOMAINS_INVALID", "verification.domains must match risk axes: " + ", ".join(sorted(required)))
            continue
        claims = [claim for claim in graph.get("claims", []) if risk["id"] in claim.get("subjects", []) and claim.get("critical") is True]
        if not claims:
            add(risk["id"], "HIGH_RISK_CLAIM_MISSING", "Domain verification requires a critical Claim containing this Risk")
        for domain, contract in sorted(domains.items()):
            if not isinstance(contract, dict) or set(contract) != {"context", "checks"}:
                add(risk["id"], "HIGH_RISK_DOMAIN_INVALID", f"{domain} requires exactly context and checks")
                continue
            roles, errors = domain_roles(domain, contract["context"], axes)
            for error in errors:
                add(risk["id"], "HIGH_RISK_CONTEXT_INVALID", f"{domain}: {error}")
            checks = contract["checks"]
            if not isinstance(checks, dict) or set(checks) != roles:
                add(risk["id"], "HIGH_RISK_CHECKS_MISSING", f"{domain} requires measured checks: " + ", ".join(sorted(roles)))
                continue
            sources: set[tuple[str, str]] = set()
            for role, assertion_id in sorted(checks.items()):
                assertion = nodes.get(assertion_id, {}) if isinstance(assertion_id, str) else {}
                aa = assertion.get("attributes", {})
                oracle = aa.get("oracle", {})
                proof_ids = {edge["target"] for edge in edges if edge.get("type") == "proves" and edge.get("source") == assertion_id and nodes.get(edge.get("target"), {}).get("type") == "Proof"}
                matching = [claim for claim in claims if proof_ids & set(claim.get("proof_ids", [])) and set(aa.get("subject_ids", [])) & set(claim.get("subjects", []))]
                valid_source = isinstance(oracle.get("source"), str) and oracle["source"].startswith("/observation/") and oracle["source"] not in {"/observation/challenge_nonce", "/observation/target_identity", "/observation/target_attestation"}
                strong = bool(proof_ids) and all(nodes[pid].get("attributes", {}).get("proof_type") in {"invariant", "runtime"} for pid in proof_ids)
                if assertion.get("type") != "Assertion" or not matching or not strong or not valid_source or oracle.get("operator") not in {"eq", "lte", "gte"} or oracle.get("expected") is None or type(oracle.get("expected")) is bool:
                    add(risk["id"], "HIGH_RISK_CHECK_INVALID", f"{domain}.{role} requires a measured Assertion on this Risk's critical Claim and runtime/invariant Proof")
                    continue
                if role == "denied_side_effects" and (oracle.get("operator") != "eq" or type(oracle.get("expected")) is not int or oracle["expected"] != 0):
                    add(risk["id"], "HIGH_RISK_DENIAL_SIDE_EFFECTS", "Denied operations must assert exactly zero side effects")
                if role == "revocation_window" and (oracle.get("operator") != "lte" or type(oracle.get("expected")) is not int or oracle["expected"] != contract["context"].get("revocation_max_seconds")):
                    add(risk["id"], "HIGH_RISK_REVOCATION_WINDOW", "Revocation evidence must bound observed post-revocation access by the declared maximum seconds")
                measurements = {(pid, oracle["source"]) for pid in proof_ids}
                if sources & measurements:
                    add(risk["id"], "HIGH_RISK_CHECK_ALIAS", f"{domain} roles cannot reuse the same measurement")
                sources |= measurements
    return issues


def evidence_symbol_ids(graph: dict[str, Any], selected: set[str] | None = None) -> set[str]:
    result: set[str] = set()
    for node in graph.get("nodes", []):
        if node.get("type") != "Risk" or (selected is not None and node.get("id") not in selected):
            continue
        verification = node.get("attributes", {}).get("verification", {})
        if isinstance(verification, dict) and isinstance(verification.get("symbols"), list):
            result.update(item for item in verification["symbols"] if isinstance(item, str))
    return result

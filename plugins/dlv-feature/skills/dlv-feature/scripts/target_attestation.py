#!/usr/bin/env python3
"""Kernel-owned verification for target-signed runtime challenge attestations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from delivery_proof import value_digest


SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
MAX_COMPACT_SEGMENT_CHARS = 16_384
MAX_RSA_MODULUS_CHARS = 2_048


def _decode_base64url(value: Any, label: str, *, max_chars: int = MAX_COMPACT_SEGMENT_CHARS) -> bytes:
    if (
        not isinstance(value, str) or not value or len(value) > max_chars
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"target attestation {label} is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"target attestation {label} is invalid") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError(f"target attestation {label} is not canonical base64url")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("target attestation JSON contains duplicate keys")
        value[key] = item
    return value


def validate_attestation_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "algorithm", "issuer", "audience", "public_key_jwk", "source_ref", "source_sha256",
    }:
        raise ValueError("target attestation config has an invalid shape")
    if value.get("algorithm") != "RS256" or not all(
        isinstance(value.get(key), str) and value[key].strip() for key in ("issuer", "audience", "source_ref")
    ):
        raise ValueError("target attestation algorithm/identity is invalid")
    if not isinstance(value.get("source_sha256"), str) or len(value["source_sha256"]) != 64:
        raise ValueError("target attestation source digest is invalid")
    jwk = value.get("public_key_jwk")
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "kid", "n", "e"} or jwk.get("kty") != "RSA":
        raise ValueError("target attestation RSA JWK has an invalid shape")
    if not isinstance(jwk.get("kid"), str) or not jwk["kid"].strip():
        raise ValueError("target attestation RSA JWK kid is invalid")
    modulus = int.from_bytes(_decode_base64url(jwk.get("n"), "JWK modulus", max_chars=MAX_RSA_MODULUS_CHARS), "big")
    exponent = int.from_bytes(_decode_base64url(jwk.get("e"), "JWK exponent", max_chars=16), "big")
    if not 2048 <= modulus.bit_length() <= 8192 or exponent != 65537:
        raise ValueError("target attestation RSA key is too weak or invalid")
    return value


def attestation_key_digest(config: dict[str, Any]) -> str:
    validate_attestation_config(config)
    return value_digest(config["public_key_jwk"])


def signed_measurement(observation: dict[str, Any]) -> dict[str, Any]:
    """Exclude transport-only fields whose local paths change when anchored."""
    return {
        key: value for key, value in observation.items()
        if key not in {"target_attestation", "anchor_paths"}
    }


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict[str, Any]) -> None:
    modulus_bytes = _decode_base64url(jwk["n"], "JWK modulus")
    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(_decode_base64url(jwk["e"], "JWK exponent"), "big")
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width:
        raise ValueError("target attestation signature width is invalid")
    signature_value = int.from_bytes(signature, "big")
    if signature_value >= modulus:
        raise ValueError("target attestation signature representative is invalid")
    encoded = pow(signature_value, exponent, modulus).to_bytes(width, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding_length = width - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    if padding_length < 8 or not hmac.compare_digest(encoded, expected):
        raise ValueError("target attestation signature verification failed")


def verify_target_attestation(
    observation: dict[str, Any], authenticity: dict[str, Any], challenge_nonce: str,
) -> dict[str, Any]:
    config = validate_attestation_config(authenticity.get("attestation"))
    compact = observation.get("target_attestation")
    if not isinstance(compact, str) or compact.count(".") != 2:
        raise ValueError("high-strength Proof requires a target-signed attestation")
    encoded_header, encoded_payload, encoded_signature = compact.split(".")
    try:
        header = json.loads(
            _decode_base64url(encoded_header, "header").decode("utf-8"), object_pairs_hook=_unique_object,
        )
        payload = json.loads(
            _decode_base64url(encoded_payload, "payload").decode("utf-8"), object_pairs_hook=_unique_object,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("target attestation JSON is invalid") from exc
    if header != {"alg": "RS256", "kid": config["public_key_jwk"]["kid"], "typ": "DLV-TARGET-ATTESTATION"}:
        raise ValueError("target attestation header is invalid")
    required = {
        "issuer", "audience", "challenge_nonce", "target_identity",
        "build_identity", "deployment_identity", "measurement_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("target attestation payload has an invalid shape")
    expected = {
        "issuer": config["issuer"],
        "audience": config["audience"],
        "challenge_nonce": challenge_nonce,
        "target_identity": authenticity.get("target_identity"),
        "build_identity": authenticity.get("build_identity"),
        "deployment_identity": authenticity.get("deployment_identity"),
        "measurement_sha256": value_digest(signed_measurement(observation)),
    }
    if payload != expected:
        raise ValueError("target attestation identity/challenge/measurement binding is stale")
    _verify_rs256(
        f"{encoded_header}.{encoded_payload}".encode("ascii"),
        _decode_base64url(encoded_signature, "signature"),
        config["public_key_jwk"],
    )
    return payload

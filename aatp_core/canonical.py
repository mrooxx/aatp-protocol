"""
aatp_core/canonical.py — RFC 8785 JSON Canonicalization Scheme (JCS)

Produces deterministic canonical JSON bytes for hashing and signing.
Two implementations processing the same logical record MUST produce
byte-identical output.

Strategy: Uses json.dumps for string serialization (reliable escaping),
custom logic only for float formatting, key sorting, and negative zero.
External jcs library used when available (Execution Plan Memo 1).

Reference: https://www.rfc-editor.org/rfc/rfc8785
"""

from __future__ import annotations

import json
import math
from typing import Any


# ---------------------------------------------------------------------------
# Try external library first (Execution Plan Memo 1)
# ---------------------------------------------------------------------------

_USE_EXTERNAL_JCS = False

try:
    import jcs as _jcs_lib
    _USE_EXTERNAL_JCS = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def canonicalize(obj: Any) -> bytes:
    """Serialize a JSON-compatible Python object to canonical JSON bytes.

    This is the single entry point for all canonical serialization in AATP.
    Returns deterministic UTF-8 bytes suitable for hashing.

    Raises:
        ValueError: If input contains NaN, Infinity.
        TypeError: If input contains non-JSON types.
    """
    if _USE_EXTERNAL_JCS:
        return _jcs_lib.canonicalize(obj)
    return _canonicalize_value(obj).encode("utf-8")


def canonicalize_record(record) -> bytes:
    """Canonicalize an AuditRecord's hashable fields.

    Pipeline: record.hashable_dict() → canonicalize() → SHA-256 → sign
    """
    return canonicalize(record.hashable_dict())


# ---------------------------------------------------------------------------
# Built-in RFC 8785 implementation
# ---------------------------------------------------------------------------

def _canonicalize_value(value: Any) -> str:
    """Recursively serialize a value to canonical JSON string."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        # Must check bool before int (bool is subclass of int)
        return "true" if value else "false"
    if isinstance(value, int):
        return _serialize_integer(value)
    if isinstance(value, float):
        return _serialize_float(value)
    if isinstance(value, str):
        # Delegate string escaping to json.dumps — it handles all
        # control characters, Unicode, and escape sequences correctly.
        # ensure_ascii=False passes non-ASCII through as UTF-8 (RFC 8785).
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        items = ",".join(_canonicalize_value(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        return _serialize_object(value)
    raise TypeError(
        f"Cannot canonicalize type {type(value).__name__}. "
        f"Only JSON-compatible types are allowed."
    )


def _serialize_integer(n: int) -> str:
    """Serialize an integer. Reject values beyond IEEE 754 double range."""
    if abs(n) > 2**53:
        raise ValueError(
            f"Integer {n} exceeds IEEE 754 double precision range (2^53). "
            f"Cannot guarantee cross-implementation consistency."
        )
    return str(n)


def _serialize_float(f: float) -> str:
    """Serialize a float per RFC 8785 / ECMAScript NumberToString.

    - NaN and Infinity are rejected (not valid JSON).
    - Negative zero is serialized as "0".
    - Otherwise: shortest representation that round-trips exactly.
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError(
            f"Cannot canonicalize {f}: NaN and Infinity are not valid JSON"
        )
    if f == 0.0:
        return "0"  # Covers both +0.0 and -0.0
    return _es6_number_to_string(f)


def _es6_number_to_string(f: float) -> str:
    """Convert float to string matching ECMAScript Number.toString()."""
    s = repr(f)

    if "e" in s or "E" in s:
        return _normalize_exponential(s)

    if "." in s:
        int_part, frac_part = s.split(".")
        frac_stripped = frac_part.rstrip("0")
        if frac_stripped:
            return f"{int_part}.{frac_stripped}"
        else:
            return int_part

    return s


def _normalize_exponential(s: str) -> str:
    """Normalize exponential notation to match ES6."""
    s = s.lower()
    mantissa, exp_str = s.split("e")
    exp_sign = "+" if not exp_str.startswith("-") else "-"
    exp_val = exp_str.lstrip("+-")
    exp_num = int(exp_val)

    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
        frac_stripped = frac_part.rstrip("0")
        if frac_stripped:
            mantissa = f"{int_part}.{frac_stripped}"
        else:
            mantissa = int_part

    return f"{mantissa}e{exp_sign}{exp_num}"


def _serialize_object(obj: dict) -> str:
    """Serialize object with keys sorted per RFC 8785 §3.2.3.

    Keys sorted by UTF-16 code unit values. For AATP's ASCII field names,
    this equals Unicode code point order equals Python's default sort.
    """
    for k in obj.keys():
        if not isinstance(k, str):
            raise TypeError(f"Dict key must be string, got {type(k).__name__}: {k!r}")

    sorted_keys = sorted(obj.keys(), key=_utf16_sort_key)
    pairs = []
    for key in sorted_keys:
        k_str = json.dumps(key, ensure_ascii=False)
        v_str = _canonicalize_value(obj[key])
        pairs.append(f"{k_str}:{v_str}")
    return "{" + ",".join(pairs) + "}"


def _utf16_sort_key(s: str) -> list[int]:
    """Sort key based on UTF-16 code units (RFC 8785 requirement)."""
    encoded = s.encode("utf-16-be")
    return [
        int.from_bytes(encoded[i : i + 2], "big")
        for i in range(0, len(encoded), 2)
    ]

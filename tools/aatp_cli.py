#!/usr/bin/env python3
"""
AATP CLI — Human-readable audit trail viewer.

Usage:
    python -m tools.aatp_cli view <trail.json>
    python -m tools.aatp_cli view <trail.json> --compact
    python -m tools.aatp_cli verify <trail.json>

Commands:
    view    — Render audit trail as formatted, readable output
    verify  — Recompute hashes and check chain integrity

Reference: AATP Execution Plan §2B.3
"""

import argparse
import json
import os
import sys
import copy

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aatp_core.canonical import canonicalize
from aatp_core.crypto import sha256_hex


# ============================================================
# Icons and formatting
# ============================================================

ICONS = {
    "initiation": "🟢",
    "termination": "🏁",
    "payment_sent": "💰",
    "payment_confirmed": "💵",
    "closing": "❌",
    "offer": "📋",
    "counter_offer": "🔄",
    "opening": "📈",
    "agreement_or_rejection": "✅",
    "problem_or_dispute": "⚠️",
    "periodic_status": "📊",
    "extension": "🔧",
}

LABELS = {
    "initiation": "SESSION START",
    "termination": "SESSION END",
    "payment_sent": "PAYMENT",
    "payment_confirmed": "PAYMENT CONFIRMED",
    "closing": "CANCELLATION",
    "offer": "RECOMMENDATION",
    "counter_offer": "COUNTER-OFFER",
    "opening": "OPPORTUNITY",
    "agreement_or_rejection": "DECISION",
    "problem_or_dispute": "ISSUE",
    "periodic_status": "STATUS",
    "extension": "EXTENSION",
}


def fmt_hash(h: str | None, length: int = 16) -> str:
    """Abbreviate a hash for display."""
    if h is None:
        return "(genesis)"
    return f"{h[:length]}..."


# ============================================================
# View command
# ============================================================

def cmd_view(trail: list[dict], compact: bool = False) -> None:
    """Render the audit trail in human-readable format."""
    if not trail:
        print("  (empty trail)")
        return

    # Extract session info from first record
    first = trail[0]
    session_id = first["header"]["session_id"]
    mode = first["header"]["mode"]
    principal = first["authorization"]["principal_did"]
    agent = first["authorization"]["agent_did"]

    # Session purpose from initiation
    purpose = first["structured_data"].get("purpose", "unknown")

    print(f"━━━ Session: {session_id[:20]}... ━━━")
    print(f"Mode: {mode.capitalize()} | Language: {first['header'].get('audit_language', 'en')} | Principal: {principal}")
    print(f"Agent: {agent[:40]}...")
    print(f"Purpose: {purpose}")

    for record in trail:
        seq = record["chain"]["sequence_number"]
        apt = record["header"]["audit_point_type"]
        icon = ICONS.get(apt, "📌")
        label = LABELS.get(apt, apt.upper())
        ts = record["header"]["timestamp"]

        # Format timestamp (handle both string and parsed)
        if isinstance(ts, str) and len(ts) > 19:
            ts_display = ts[:19] + "Z"
        else:
            ts_display = str(ts)

        print(f"\n[{seq}] {icon} {label} | {ts_display}")

        # Narrative
        narrative = record["narrative"]
        if compact and len(narrative) > 100:
            narrative = narrative[:97] + "..."

        # Indent narrative nicely
        lines = _wrap_text(narrative, width=64)
        for line in lines:
            print(f"    {line}")

        # Structured data summary
        sd = record["structured_data"]
        if not compact:
            # Show key fields inline
            display_keys = [
                k for k in sd.keys()
                if k not in ("recorder_flags", "session_digest", "record_count")
            ]
            if display_keys:
                parts = []
                for k in display_keys[:6]:  # limit display
                    v = sd[k]
                    if isinstance(v, float):
                        parts.append(f"{k}: {v:.2f}")
                    elif isinstance(v, str) and len(v) > 30:
                        parts.append(f"{k}: \"{v[:27]}...\"")
                    else:
                        parts.append(f"{k}: {json.dumps(v)}")
                print(f"    ─── Data: {{{', '.join(parts)}}} ───")

        # Recorder flags
        flags = sd.get("recorder_flags", [])
        if flags:
            for flag in flags:
                print(f"    ⚠ FLAG: {flag}")

    # Final summary if termination exists
    last = trail[-1]
    if last["header"]["audit_point_type"] == "termination":
        sd = last["structured_data"]
        digest = sd.get("session_digest", "?")
        count = sd.get("record_count", len(trail) - 1)
        print(f"\n━━━ Session Summary ━━━")
        print(f"Records: {count + 1} (incl. termination)")
        print(f"Digest: {fmt_hash(digest, 24)}")


def _wrap_text(text: str, width: int = 64) -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines = []
    current = []
    length = 0

    for word in words:
        if length + len(word) + 1 > width and current:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += len(word) + 1

    if current:
        lines.append(" ".join(current))

    return lines if lines else [""]


# ============================================================
# Verify command
# ============================================================

def cmd_verify(trail: list[dict]) -> None:
    """Verify chain integrity from a JSON trail file."""
    if not trail:
        print("  (empty trail)")
        return

    print(f"━━━ Chain Verification ━━━")
    print(f"Records: {len(trail)}")

    errors = []
    prev_hash = None

    for i, record in enumerate(trail):
        seq = record["chain"]["sequence_number"]
        stored_hash = record["chain"]["record_hash"]

        # Recompute hash
        hashable = copy.deepcopy(record)
        hashable["chain"].pop("record_hash", None)
        hashable["chain"].pop("signature", None)
        computed_hash = sha256_hex(canonicalize(hashable))

        # Check hash
        hash_ok = (stored_hash == computed_hash)

        # Check chain link
        expected_prev = record["chain"]["previous_hash"]
        link_ok = (expected_prev == prev_hash)

        if hash_ok and link_ok:
            apt = record["header"]["audit_point_type"]
            print(f"  ✓ seq #{seq:2d} [{apt:25s}] hash OK, link OK")
        else:
            if not hash_ok:
                errors.append(
                    f"seq #{seq}: hash MISMATCH "
                    f"(stored: {stored_hash[:16]}..., "
                    f"computed: {computed_hash[:16]}...)"
                )
                print(f"  ✗ seq #{seq:2d} HASH MISMATCH")
            if not link_ok:
                errors.append(
                    f"seq #{seq}: chain link broken "
                    f"(expected prev: {fmt_hash(prev_hash)}, "
                    f"actual: {fmt_hash(expected_prev)})"
                )
                print(f"  ✗ seq #{seq:2d} CHAIN LINK BROKEN")

        prev_hash = stored_hash

    print()
    if not errors:
        print(f"  Result: ✓ CHAIN INTACT ({len(trail)} records verified)")
    else:
        print(f"  Result: ✗ CHAIN COMPROMISED ({len(errors)} error(s))")
        for e in errors:
            print(f"    • {e}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="AATP CLI — Audit trail viewer and verifier",
        prog="python -m tools.aatp_cli",
    )
    parser.add_argument(
        "command",
        choices=["view", "verify"],
        help="Command: view (render trail) or verify (check integrity)",
    )
    parser.add_argument(
        "trail_file",
        help="Path to trail.json file",
    )
    parser.add_argument(
        "--compact", "-c",
        action="store_true",
        help="Compact view (truncate long narratives)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.trail_file):
        print(f"  ERROR: File not found: {args.trail_file}")
        sys.exit(1)

    with open(args.trail_file, "r", encoding="utf-8") as f:
        trail = json.load(f)

    if args.command == "view":
        cmd_view(trail, compact=args.compact)
    elif args.command == "verify":
        cmd_verify(trail)


if __name__ == "__main__":
    main()

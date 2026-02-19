"""UUID v7 generation (time-ordered).

Implements RFC 9562 UUID v7: unix_ts_ms + random.
Time-ordered IDs are preferred over UUID v4 for audit records because
they sort chronologically, aiding both storage indexing and human review.

No external dependency required.

Adopted from AATP v0.1 implementation.
"""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> str:
    """Generate a UUID v7 (time-ordered).

    Format: 48-bit unix_ts_ms | 4-bit version(7) | 12-bit rand_a
            | 2-bit variant | 62-bit rand_b
    """
    timestamp_ms = int(time.time() * 1000)

    # 48-bit timestamp
    ts_bytes = timestamp_ms.to_bytes(6, byteorder="big")

    # 10 bytes of randomness
    rand_bytes = os.urandom(10)

    # Assemble 16 bytes
    uuid_bytes = bytearray(16)
    uuid_bytes[0:6] = ts_bytes
    uuid_bytes[6:16] = rand_bytes

    # Set version (bits 48-51 = 0111 = 7)
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x70

    # Set variant (bits 64-65 = 10)
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80

    return str(uuid.UUID(bytes=bytes(uuid_bytes)))

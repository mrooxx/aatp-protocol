"""
AATP Core — Auditable Agent Transaction Protocol reference implementation.

__version__ is the SDK version. Protocol version is tracked separately
in RecordHeader.protocol_version and follows its own semver cadence.
"""

__version__ = "0.1.0"

from .uuid7 import uuid7
from .record import (
    AuditRecord,
    AuditPointType,
    OperatingMode,
    RecordHeader,
    Authorization,
    Counterparty,
    Signature,
    ChainMeta,
    MAX_RECORD_SIZE_BYTES,
    validate_record_size,
    export_json_schema,
)
from .canonical import canonicalize, canonicalize_record
from .crypto import (
    sha256_hex,
    generate_keypair,
    sign_bytes,
    verify_signature,
    private_key_to_pem,
    public_key_to_pem,
    private_key_from_pem,
    public_key_from_pem,
    public_key_to_did_key,
)
from .chain import (
    seal_record,
    verify_record,
    verify_chain,
    compute_session_digest,
)
from .storage import Storage
from .session import AuditSession, SessionState

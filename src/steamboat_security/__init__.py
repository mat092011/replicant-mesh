"""Transport-neutral participant identity, enrollment, and scoped admission core.

The package imports no Torch and does not install or configure a transport.
"""

from .authorization import (Authorization, Authorizer, LocalIdentity,
                            ScopeAuthorization, authorize_scope)
from .certificates import (MAX_LEAF_LIFETIME_SECONDS, certificate_sha256,
                           generate_ca, generate_private_key_pem, identity_uri,
                           issue_leaf, make_csr, public_key_sha256,
                           serial_hex, verify_ca, verify_expected_server_leaf,
                           verify_leaf)
from .clock import Clock
from .codec import (MAX_BINDING_BYTES, MAX_METADATA_BYTES, METADATA_KEY,
                    Binding, canonical_json, encode_binding, parse_metadata)
from .errors import (BindingError, ClockError, CredentialError, ScopeError,
                     SecurityError, SessionError, SnapshotError, StorageError)
from .files import safe_read, safe_write
from .ids import new_boot_id, new_id, validate_boot, validate_id
from .operator import (InvitationRegistry, create_invitation,
                       enroll_invited, generate_authorization_signing_key_pem,
                       make_renewal_proof, publish_snapshot, renew_leaf)
from .outbound import (AuthorizationWatcher, BootstrapContext,
                       ConsumerRequestContext, OutboundAuthorization,
                       OutboundAuthorizer, OutboundTarget)
from .sessions import SessionBindings, SessionNotice
from .snapshot import (MAX_SNAPSHOT_LIFETIME_SECONDS,
                       SNAPSHOT_EXPIRY_CHECK_SECONDS, SNAPSHOT_REFRESH_SECONDS,
                       SnapshotStore, canonical_policy_digest, sign_snapshot,
                       snapshot_public_key_pem)
from .root_transition import (AffectedPrincipal, LoadedRootTransitionApproval,
                              RootTransitionDeclaration,
                              load_protected_root_transition,
                              parse_root_transition_declaration)

__all__ = [
    "Authorization", "Authorizer", "LocalIdentity", "ScopeAuthorization",
    "authorize_scope", "OutboundAuthorizer", "OutboundAuthorization",
    "OutboundTarget", "BootstrapContext", "ConsumerRequestContext",
    "AuthorizationWatcher", "Clock", "Binding",
    "SessionBindings", "SessionNotice", "SnapshotStore", "SecurityError",
    "CredentialError", "SnapshotError", "BindingError", "ScopeError",
    "SessionError", "ClockError", "StorageError", "MAX_BINDING_BYTES",
    "MAX_METADATA_BYTES", "METADATA_KEY", "MAX_LEAF_LIFETIME_SECONDS",
    "MAX_SNAPSHOT_LIFETIME_SECONDS", "SNAPSHOT_REFRESH_SECONDS",
    "SNAPSHOT_EXPIRY_CHECK_SECONDS", "generate_ca", "generate_private_key_pem",
    "identity_uri", "issue_leaf", "make_csr", "verify_ca", "verify_leaf",
    "verify_expected_server_leaf", "certificate_sha256", "public_key_sha256",
    "serial_hex", "canonical_json", "encode_binding", "parse_metadata",
    "new_id", "new_boot_id", "validate_id", "validate_boot", "safe_read",
    "safe_write", "InvitationRegistry", "create_invitation", "enroll_invited",
    "renew_leaf", "make_renewal_proof", "generate_authorization_signing_key_pem",
    "publish_snapshot", "sign_snapshot", "snapshot_public_key_pem",
    "canonical_policy_digest", "AffectedPrincipal", "RootTransitionDeclaration",
    "LoadedRootTransitionApproval", "parse_root_transition_declaration",
    "load_protected_root_transition",
]

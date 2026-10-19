"""Prepare a private, uncommitted root-transition policy and launch manifest.

This module does not publish files, approve activation, prove supervisor-observed
retirement, or establish that any prepared launch was admitted or ready.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Sequence

from cryptography.hazmat.primitives import serialization

from .certificates import (ROLE_EKUS, _csr, _key, _pem_certificate, _validate_sans, certificate_sha256,
                           identity_uri,
                           public_key_sha256, serial_hex, verify_ca, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError
from .operator import _record_from_leaf
from .root_transition import (AffectedPrincipal, RootTransitionDeclaration,
                              parse_root_transition_declaration)
from .root_transition_issuance import (ISSUANCE_MANIFEST_DOMAIN,
                                       IssuedPrincipal, PrincipalIssuanceInput,
                                       RootTransitionIssuanceCandidate,
                                       _current_authorization, _intent_document)
from .root_transition_launch import (RoleLaunchSpec, canonical_role_launch_digest,
                                    parse_role_launch_spec, role_launch_document)
from .root_transition_preparation import PreparationIntent
from .snapshot import (CredentialRecord, Grant, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_LIFETIME_SECONDS,
                       SnapshotStore, canonical_policy_digest, sign_snapshot)

MAX_ACTIVATION_MANIFEST_BYTES = 64 * 1024
ACTIVATION_MANIFEST_DOMAIN = "steamboat.root-transition.activation-manifest.v1"


@dataclass(frozen=True)
class PreparedActivationCandidate:
    transition_id: str
    preparation_intent_sha256: str
    issuance_manifest_sha256: str
    activation_manifest_sha256: str
    old_launch_digest: str
    new_launch_digest: str
    old_launch_specs: tuple[RoleLaunchSpec, ...]
    new_launch_specs: tuple[RoleLaunchSpec, ...]
    declaration: RootTransitionDeclaration
    policy_digest: str
    policy_payload: bytes
    signed_snapshot: bytes
    issuance_candidate: RootTransitionIssuanceCandidate
    activation_manifest: bytes


def _hash_json(value) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _intent_hash(intent: PreparationIntent) -> str:
    if type(intent) is not PreparationIntent:
        raise CredentialError("preparation intent has an unsupported type")
    encoded = canonical_json(_intent_document(intent))
    from .root_transition_preparation import parse_preparation_intent
    parsed = parse_preparation_intent(encoded)
    if canonical_json(_intent_document(parsed)) != encoded:
        raise CredentialError("preparation intent fields are not canonical")
    return hashlib.sha256(encoded).hexdigest()


def expected_transition_generation_sha256(intent: PreparationIntent) -> str:
    """Return the deterministic generation identity for this transition.

    It intentionally excludes launch specs, runtime configuration and manifest
    bytes, avoiding a self-referential generation/launch digest.
    """
    return hashlib.sha256(canonical_json({
        "schema_version": 1, "purpose": "root_transition_generation",
        "transition_id": intent.transition_id,
        "preparation_intent_sha256": _intent_hash(intent),
        "ca_sha256": intent.new_ca_sha256,
        "snapshot_key_sha256": intent.new_snapshot_key_sha256,
    })).hexdigest()


def _launch_tuple(values: Sequence[RoleLaunchSpec], *, label: str) -> tuple[RoleLaunchSpec, ...]:
    if type(values) not in (tuple, list) or not 1 <= len(values) <= 16:
        raise CredentialError(f"{label} launch specs must be a bounded nonempty sequence")
    parsed = []
    for value in values:
        if type(value) is not RoleLaunchSpec:
            raise CredentialError(f"{label} launch spec has an unsupported type")
        try:
            checked = parse_role_launch_spec(role_launch_document(value))
        except (BindingError, SnapshotError, TypeError, ValueError) as error:
            raise CredentialError(f"{label} launch spec is invalid") from error
        if checked != value:
            raise CredentialError(f"{label} launch spec is not canonical")
        parsed.append(checked)
    result = tuple(sorted(parsed, key=lambda item: (item.account_id, item.device_id, item.role)))
    identities = tuple((item.account_id, item.device_id, item.role) for item in result)
    if len(set(identities)) != len(identities):
        raise CredentialError(f"{label} launch specs contain duplicate identities")
    return result


def _launch_digest(specs: tuple[RoleLaunchSpec, ...]) -> str:
    return canonical_role_launch_digest(specs)


def _launch_map(specs):
    return {(item.account_id, item.device_id, item.role): item for item in specs}


def _record_document(record: CredentialRecord) -> dict:
    return {
        "account_id": record.account_id, "device_id": record.device_id,
        "role": record.role, "serial": record.serial,
        "public_key_sha256": record.public_key_sha256,
        "certificate_sha256": record.certificate_sha256,
        "credential_epoch": record.credential_epoch,
        "not_before": record.not_before, "not_after": record.not_after,
        "ekus": list(record.ekus), "dns_sans": list(record.dns_sans),
        "ip_sans": list(record.ip_sans),
    }


def _grant_document(grant: Grant) -> dict:
    return {
        "account_id": grant.account_id, "device_id": grant.device_id,
        "role": grant.role, "actor_serial": grant.actor_serial,
        "actor_public_key_sha256": grant.actor_public_key_sha256,
        "actor_credential_epoch": grant.actor_credential_epoch,
        "tenant_account_id": grant.tenant_account_id,
        "target_account_id": grant.target_account_id,
        "target_device_id": grant.target_device_id,
        "target_role": grant.target_role, "target_serial": grant.target_serial,
        "target_public_key_sha256": grant.target_public_key_sha256,
        "target_credential_epoch": grant.target_credential_epoch,
        "target_boot_id": grant.target_boot_id,
        "actor_boot_id": grant.actor_boot_id,
        "assignment_id": grant.assignment_id, "model_id": grant.model_id,
        "method": grant.method, "not_before": grant.not_before,
        "not_after": grant.not_after,
    }


def _revalidate_issuance(intent: PreparationIntent,
                         candidate: RootTransitionIssuanceCandidate,
                         new_ca_pem: bytes, sample) -> tuple[IssuedPrincipal, ...]:
    if type(candidate) is not RootTransitionIssuanceCandidate:
        raise CredentialError("activation preparation requires an issuance candidate")
    intent_hash = _intent_hash(intent)
    if (candidate.transition_id != intent.transition_id
            or candidate.intent_sha256 != intent_hash
            or candidate.old_ca_sha256 != intent.old_ca_sha256
            or candidate.new_ca_sha256 != intent.new_ca_sha256
            or candidate.old_snapshot_key_sha256 != intent.old_snapshot_key_sha256
            or candidate.new_snapshot_key_sha256 != intent.new_snapshot_key_sha256):
        raise CredentialError("issuance candidate is bound to different preparation intent")
    if type(candidate.manifest) is not bytes or len(candidate.manifest) > MAX_ACTIVATION_MANIFEST_BYTES:
        raise CredentialError("issuance manifest is malformed or oversized")
    try:
        manifest = json.loads(candidate.manifest.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("issuance manifest is malformed") from error
    expected_base = {
        "domain": ISSUANCE_MANIFEST_DOMAIN, "version": 1,
        "transition_id": intent.transition_id, "intent_sha256": intent_hash,
        "old_ca_sha256": intent.old_ca_sha256, "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
    }
    expected_manifest = {**expected_base, "principals": []}
    if (type(manifest) is not dict or set(manifest) != set(expected_base) | {"principals"}
            or canonical_json(manifest) != candidate.manifest):
        raise CredentialError("issuance manifest is not canonical or is bound to other inputs")
    if (type(candidate.principals) is not tuple
            or len(candidate.principals) != len(intent.affected_principals)):
        raise CredentialError("issuance candidate does not contain the whole declared cohort")
    issued_by_identity = {}
    actual_serials = set()
    actual_keys = set()
    old_serials = {p.old_serial for p in intent.affected_principals}
    actual_principals = []
    ca = verify_ca(new_ca_pem, now=sample.wall, uncertainty_seconds=sample.uncertainty)
    if certificate_sha256(ca) != intent.new_ca_sha256:
        raise CredentialError("new CA certificate differs from the preparation pin")
    for principal, issued in zip(intent.affected_principals, candidate.principals):
        if type(issued) is not IssuedPrincipal or issued.identity != principal.identity:
            raise CredentialError("issued principal order or identity differs from intent")
        if type(issued.certificate_pem) is not bytes:
            raise CredentialError("issued certificate bytes are malformed")
        cert = _pem_certificate(issued.certificate_pem)
        actual_raw = _record_from_leaf(
            issued.certificate_pem, account_id=principal.account_id,
            device_id=principal.device_id, role=principal.role,
            credential_epoch=principal.old_credential_epoch + 1)
        actual = CredentialRecord(
            actual_raw["account_id"], actual_raw["device_id"], actual_raw["role"],
            actual_raw["serial"], actual_raw["public_key_sha256"],
            actual_raw["certificate_sha256"], actual_raw["credential_epoch"],
            actual_raw["not_before"], actual_raw["not_after"],
            tuple(actual_raw["ekus"]), tuple(actual_raw["dns_sans"]),
            tuple(actual_raw["ip_sans"]))
        if (type(issued.record) is not CredentialRecord
                or canonical_json(_record_document(actual))
                    != canonical_json(_record_document(issued.record))):
            raise CredentialError("issued record differs from actual certificate")
        if (actual.credential_epoch != principal.old_credential_epoch + 1
                or actual.serial in old_serials or actual.serial in actual_serials
                or actual.public_key_sha256 in actual_keys
                or not set(actual.dns_sans).issubset(principal.dns_sans)
                or not set(actual.ip_sans).issubset(principal.ip_sans)):
            raise CredentialError("issued certificate changes epoch or expands declared scope")
        actual_serials.add(actual.serial)
        actual_keys.add(actual.public_key_sha256)
        verify_leaf(
            new_ca_pem, issued.certificate_pem, now=sample.wall,
            uncertainty_seconds=sample.uncertainty,
            account_id=principal.account_id, device_id=principal.device_id,
            role=principal.role, serial=actual.serial,
            public_key_hash=actual.public_key_sha256,
            certificate_hash=actual.certificate_sha256,
            ekus=tuple(sorted(ROLE_EKUS[principal.role])),
            dns_sans=actual.dns_sans, ip_sans=actual.ip_sans)
        if actual.identity in issued_by_identity:
            raise CredentialError("issuance candidate duplicates a role")
        issued_by_identity[actual.identity] = issued
        actual_principals.append({
            "account_id": actual.account_id, "device_id": actual.device_id,
            "role": actual.role, "old_serial": principal.old_serial,
            "old_credential_epoch": principal.old_credential_epoch,
            "old_admission_epoch": principal.old_admission_epoch,
            "new_serial": actual.serial,
            "new_certificate_sha256": actual.certificate_sha256,
            "new_public_key_sha256": actual.public_key_sha256,
            "new_credential_epoch": actual.credential_epoch,
            "new_csr_sha256": principal.new_csr_sha256,
            "dns_sans": list(actual.dns_sans), "ip_sans": list(actual.ip_sans),
            "ekus": list(actual.ekus), "not_before": actual.not_before,
            "not_after": actual.not_after,
        })
    expected_manifest["principals"] = actual_principals
    if canonical_json(manifest) != canonical_json(expected_manifest):
        raise CredentialError("issuance manifest does not bind the actual issued cohort")
    return tuple(candidate.principals)


def _validate_csr_bindings(intent, issued, csr_by_identity):
    """Bind caller-supplied CSR bytes to the full intent and issued leaves."""
    if type(csr_by_identity) is not dict or set(csr_by_identity) != {
            p.identity for p in intent.affected_principals}:
        raise CredentialError("public CSR map must exactly cover the affected cohort")
    issued_map = {item.identity: item for item in issued}
    intent_map = {item.identity: item for item in intent.affected_principals}
    for identity, encoded in csr_by_identity.items():
        principal = intent_map[identity]
        issued_item = issued_map[identity]
        if type(encoded) is not bytes or not encoded or hashlib.sha256(encoded).hexdigest() != principal.new_csr_sha256:
            raise CredentialError("public CSR bytes differ from the approved intent pin")
        try:
            csr = _csr(encoded)
            uri, dns, ips = _validate_sans(csr)
        except (CredentialError, ValueError, TypeError) as error:
            raise CredentialError("public CSR is invalid") from error
        record = issued_item.record
        if (uri != identity_uri(*identity)
                or public_key_sha256(csr.public_key()) != record.public_key_sha256
                or tuple(dns) != record.dns_sans or tuple(ips) != record.ip_sans
                or not set(dns).issubset(principal.dns_sans)
                or not set(ips).issubset(principal.ip_sans)):
            raise CredentialError("public CSR identity, key or SANs differ from issued leaf")


def _check_old_policy(intent, old_store, sample):
    if type(old_store) is not SnapshotStore:
        raise CredentialError("current old snapshot store is invalid")
    view = old_store.current(sample=sample)
    if view.revision != intent.old_policy_revision or view.policy_digest != intent.old_policy_digest:
        raise CredentialError("current old policy differs from preparation pins")
    old_ca = verify_ca(old_store.ca_certificate_pem, now=sample.wall,
                       uncertainty_seconds=sample.uncertainty)
    if certificate_sha256(old_ca) != intent.old_ca_sha256:
        raise CredentialError("current old CA differs from preparation pins")
    if public_key_sha256(old_store._verification_key) != intent.old_snapshot_key_sha256:
        raise CredentialError("current old snapshot signer differs from preparation pins")
    dummy_inputs = tuple(PrincipalIssuanceInput(principal, b"", b"", b"")
                         for principal in intent.affected_principals)
    checked, records = _current_authorization(old_store, intent, dummy_inputs, sample)
    return checked, records


def _check_authority_separation(intent, old_store, new_ca, new_snapshot_public,
                                current_view, issued, sample):
    old_ca = verify_ca(old_store.ca_certificate_pem, now=sample.wall,
                       uncertainty_seconds=sample.uncertainty)
    old_ca_key = public_key_sha256(old_ca.public_key())
    new_ca_key = public_key_sha256(new_ca.public_key())
    old_signer = public_key_sha256(old_store._verification_key)
    new_signer = public_key_sha256(new_snapshot_public)
    if (old_signer != intent.old_snapshot_key_sha256
            or new_signer != intent.new_snapshot_key_sha256
            or certificate_sha256(old_ca) != intent.old_ca_sha256
            or certificate_sha256(new_ca) != intent.new_ca_sha256):
        raise CredentialError("root transition authorities differ from intent pins")
    if (old_ca_key in (old_signer, new_signer)
            or new_ca_key in (old_signer, new_signer)):
        raise CredentialError("CA keys must remain separate from snapshot signer keys")
    old_role_keys = {record.public_key_sha256 for record in current_view.credentials_by_serial.values()}
    role_keys = set(old_role_keys)
    role_keys.update(item.record.public_key_sha256 for item in issued)
    authorities = {old_ca_key, new_ca_key, old_signer, new_signer}
    if role_keys.intersection(authorities):
        raise CredentialError("authority keys must be separate from all current and issued role keys")
    issued_keys = [item.record.public_key_sha256 for item in issued]
    if len(issued_keys) != len(set(issued_keys)) or old_role_keys.intersection(issued_keys):
        raise CredentialError("issued role keys must be unique and fresh from all old role keys")


def _normalize_launches(intent, issued, old_specs, new_specs):
    old = _launch_tuple(old_specs, label="old")
    new = _launch_tuple(new_specs, label="new")
    principals = {item.identity: item for item in intent.affected_principals}
    issued_map = {item.identity: item.record for item in issued}
    identities = set(principals)
    if set(_launch_map(old)) != identities or set(_launch_map(new)) != identities:
        raise CredentialError("old and new launch plans must exactly cover affected principals")
    old_map, new_map = _launch_map(old), _launch_map(new)
    old_boots = set()
    new_boots = set()
    old_generations = {item.generation_sha256 for item in old}
    expected_generation = expected_transition_generation_sha256(intent)
    if len(old_generations) != 1 or expected_generation in old_generations:
        raise CredentialError("old launch plans must share one generation distinct from new generation")
    for identity, principal in principals.items():
        before, after, record = old_map[identity], new_map[identity], issued_map[identity]
        if (before.serial != principal.old_serial
                or before.certificate_sha256 != principal.old_certificate_sha256
                or before.public_key_sha256 != principal.old_public_key_sha256
                or before.credential_epoch != principal.old_credential_epoch
                or before.admission_epoch != principal.old_admission_epoch
                or before.boot_id != principal.old_boot_id):
            raise CredentialError("old launch plan does not match declared old credential/boot pins")
        if (after.serial != record.serial
                or after.certificate_sha256 != record.certificate_sha256
                or after.public_key_sha256 != record.public_key_sha256
                or after.credential_epoch != principal.old_credential_epoch + 1
                or after.admission_epoch != principal.old_admission_epoch + 1):
            raise CredentialError("new launch plan does not match issued credential and next epochs")
        if after.generation_sha256 != expected_generation:
            raise CredentialError("new launch plan has the wrong deterministic transition generation")
        old_boots.add(before.boot_id)
        new_boots.add(after.boot_id)
    if len(new_boots) != len(new):
        raise CredentialError("new launch boot IDs must be unique")
    if new_boots.intersection(old_boots):
        raise CredentialError("new launch boot IDs must be fresh across the cohort")
    return old, new, old_map, new_map


def _policy_grants(old_view, sample, old_map, new_map, issued_map,
                   retained_old_grants, intent, expires_at):
    active = tuple(g for g in old_view.active_grants(sample))
    if retained_old_grants is None:
        principal_by_serial = {p.old_serial: p for p in intent.affected_principals}
        selected_items = []
        for grant in active:
            actor = principal_by_serial.get(grant.actor_serial)
            target = principal_by_serial.get(grant.target_serial)
            if actor is None or target is None:
                continue
            if grant.target_boot_id != old_map[target.identity].boot_id:
                continue
            if (grant.actor_boot_id is not None
                    and grant.actor_boot_id != old_map[actor.identity].boot_id):
                continue
            selected_items.append(grant)
        selected = tuple(selected_items)
    else:
        if type(retained_old_grants) not in (tuple, list):
            raise CredentialError("retained grants must be an exact sequence")
        selected = tuple(retained_old_grants)
        if (any(type(g) is not Grant for g in selected)
                or len(set(selected)) != len(selected)
                or any(g not in active for g in selected)):
            raise CredentialError("retained grants must be a unique subset of current active grants")
    principal_by_serial = {p.old_serial: p for p in intent.affected_principals}
    retained = []
    retained_roles = set()
    for old_grant in selected:
        actor_principal = principal_by_serial.get(old_grant.actor_serial)
        target_principal = principal_by_serial.get(old_grant.target_serial)
        if actor_principal is None or target_principal is None:
            raise CredentialError("retained grant endpoint is outside the issued cohort")
        if (old_grant.target_boot_id != old_map[target_principal.identity].boot_id
                or (old_grant.actor_boot_id is not None
                    and old_grant.actor_boot_id != old_map[actor_principal.identity].boot_id)):
            raise CredentialError("retained grant boot pins differ from the old launch plan")
        actor = issued_map[actor_principal.identity]
        target = issued_map[target_principal.identity]
        actor_launch = new_map[actor_principal.identity]
        target_launch = new_map[target_principal.identity]
        actor_boot = None if old_grant.actor_boot_id is None else actor_launch.boot_id
        start = max(old_grant.not_before, intent.overlap_not_before,
                    actor.not_before, target.not_before, int(sample.earliest_wall))
        stop = min(old_grant.not_after, intent.overlap_not_after,
                   actor.not_after, target.not_after, expires_at)
        if stop <= start or stop <= sample.latest_wall:
            raise CredentialError("retained grant has no conservative valid interval")
        retained.append(Grant(
            old_grant.account_id, old_grant.device_id, old_grant.role,
            actor.serial, actor.public_key_sha256, actor.credential_epoch,
            old_grant.tenant_account_id, old_grant.target_account_id,
            old_grant.target_device_id, old_grant.target_role,
            target.serial, target.public_key_sha256, target.credential_epoch,
            target_launch.boot_id, actor_boot, old_grant.assignment_id,
            old_grant.model_id, old_grant.method, start, stop))
        retained_roles.update((actor_principal.identity, target_principal.identity))
    if retained_roles != set(issued_map):
        raise CredentialError("every issued role must retain at least one active scoped grant")
    return tuple(sorted(retained, key=lambda item: canonical_json(_grant_document(item))))


def _declaration_document(intent: PreparationIntent, policy_digest: str) -> dict:
    return {
        "schema_version": 1, "transition_id": intent.transition_id,
        "old_ca_sha256": intent.old_ca_sha256, "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "overlap_not_before": intent.overlap_not_before,
        "overlap_not_after": intent.overlap_not_after,
        "old_policy_revision": intent.old_policy_revision,
        "old_policy_digest": intent.old_policy_digest,
        "next_minimum_revision": intent.next_minimum_revision,
        "new_policy_digest": policy_digest,
        "affected_principals": [
            {"account_id": p.account_id, "device_id": p.device_id, "role": p.role,
             "old_boot_id": p.old_boot_id, "old_serial": p.old_serial,
             "old_certificate_sha256": p.old_certificate_sha256,
             "old_public_key_sha256": p.old_public_key_sha256,
             "old_credential_epoch": p.old_credential_epoch,
             "old_admission_epoch": p.old_admission_epoch,
             "new_csr_sha256": p.new_csr_sha256,
             "dns_sans": list(p.dns_sans), "ip_sans": list(p.ip_sans)}
            for p in intent.affected_principals],
    }


def _assert_overlap(intent, sample):
    if (sample.earliest_wall < intent.overlap_not_before
            or sample.latest_wall >= intent.overlap_not_after):
        raise CredentialError("trusted clock interval is outside transition overlap")


def _validate_policy_grants(old_view, new_view, intent, issued, new_specs, sample):
    principals = {p.old_serial: p for p in intent.affected_principals}
    issued_by_old = {p.old_serial: next(i.record for i in issued if i.identity == p.identity)
                     for p in intent.affected_principals}
    launch_by_identity = _launch_map(new_specs)
    old_grants = old_view.active_grants(sample)
    used_old = set()
    covered = set()
    new_active = new_view.active_grants(sample)
    if len(new_active) != len(new_view.grants):
        raise CredentialError("candidate policy contains a grant that is not currently active")
    for grant in new_active:
        actor_principal = next((p for p in principals.values()
                                if issued_by_old[p.old_serial].serial == grant.actor_serial), None)
        target_principal = next((p for p in principals.values()
                                 if issued_by_old[p.old_serial].serial == grant.target_serial), None)
        if actor_principal is None or target_principal is None:
            raise CredentialError("new policy grant endpoint is outside the issued cohort")
        old_actor = issued_by_old[actor_principal.old_serial]
        old_target = issued_by_old[target_principal.old_serial]
        actor_spec = launch_by_identity[actor_principal.identity]
        target_spec = launch_by_identity[target_principal.identity]
        if (grant.actor_public_key_sha256 != old_actor.public_key_sha256
                or grant.actor_credential_epoch != old_actor.credential_epoch
                or grant.target_public_key_sha256 != old_target.public_key_sha256
                or grant.target_credential_epoch != old_target.credential_epoch
                or grant.target_boot_id != target_spec.boot_id):
            raise CredentialError("new grant does not follow issued credentials and launch boots")
        candidates = [old for old in old_grants if old.identity not in used_old
            and (old.account_id, old.device_id, old.role, old.tenant_account_id,
                 old.target_account_id, old.target_device_id, old.target_role,
                 old.assignment_id, old.model_id, old.method)
                == (grant.account_id, grant.device_id, grant.role, grant.tenant_account_id,
                    grant.target_account_id, grant.target_device_id, grant.target_role,
                    grant.assignment_id, grant.model_id, grant.method)
            and old.actor_serial == actor_principal.old_serial
            and old.target_serial == target_principal.old_serial]
        if len(candidates) != 1:
            raise CredentialError("new grant is not a unique permission-preserving old grant")
        old = candidates[0]
        expected_actor_boot = None if old.actor_boot_id is None else actor_spec.boot_id
        if (grant.actor_boot_id != expected_actor_boot
                or old.target_boot_id != target_principal.old_boot_id
                or (old.actor_boot_id is not None
                    and old.actor_boot_id != actor_principal.old_boot_id)
                or grant.not_before < old.not_before
                or grant.not_after > old.not_after
                or grant.not_before < intent.overlap_not_before
                or grant.not_after > intent.overlap_not_after
                or grant.not_before < old_actor.not_before
                or grant.not_before < old_target.not_before
                or grant.not_after > old_actor.not_after
                or grant.not_after > old_target.not_after
                or grant.not_after > new_view.expires_at
                or grant.not_after <= sample.latest_wall):
            raise CredentialError("new grant expands permission time or violates candidate bounds")
        used_old.add(old.identity)
        covered.update((actor_principal.identity, target_principal.identity))
    if covered != {p.identity for p in intent.affected_principals}:
        raise CredentialError("each issued role must retain an active scoped grant")


def validate_prepared_activation_candidate(
        *, candidate: PreparedActivationCandidate, intent: PreparationIntent,
        old_snapshot_store: SnapshotStore, new_ca_certificate_pem: bytes,
        new_snapshot_public_key_pem: bytes, new_csr_by_identity: dict, clock: Clock):
    """Revalidate the immutable public candidate before separate final approval."""
    if type(candidate) is not PreparedActivationCandidate or type(intent) is not PreparationIntent:
        raise CredentialError("prepared activation candidate has an unsupported type")
    if candidate.transition_id != intent.transition_id:
        raise CredentialError("candidate transition ID differs from preparation intent")
    if (type(candidate.policy_payload) is not bytes
            or not 1 <= len(candidate.policy_payload) <= MAX_SNAPSHOT_BYTES):
        raise CredentialError("candidate policy payload is malformed or oversized")
    if old_snapshot_store.clock is not clock:
        raise CredentialError("candidate and old snapshot must share the configured clock")
    sample = clock.sample()
    _assert_overlap(intent, sample)
    issued = _revalidate_issuance(intent, candidate.issuance_candidate,
                                  new_ca_certificate_pem, sample)
    _validate_csr_bindings(intent, issued, new_csr_by_identity)
    old_view, old_records = _check_old_policy(intent, old_snapshot_store, sample)
    old_specs, new_specs, _, _ = _normalize_launches(
        intent, candidate.issuance_candidate.principals,
        candidate.old_launch_specs, candidate.new_launch_specs)
    if (old_specs != candidate.old_launch_specs or new_specs != candidate.new_launch_specs
            or _launch_digest(old_specs) != candidate.old_launch_digest
            or _launch_digest(new_specs) != candidate.new_launch_digest):
        raise CredentialError("candidate launch plans or digests are inconsistent")
    new_ca = verify_ca(new_ca_certificate_pem, now=sample.wall,
                       uncertainty_seconds=sample.uncertainty)
    public_key = serialization.load_pem_public_key(new_snapshot_public_key_pem)
    if public_key_sha256(public_key) != intent.new_snapshot_key_sha256:
        raise CredentialError("candidate snapshot signer differs from preparation pin")
    _check_authority_separation(intent, old_snapshot_store, new_ca, public_key,
                                old_view, issued, sample)
    if (type(candidate.activation_manifest) is not bytes
            or not 1 <= len(candidate.activation_manifest) <= MAX_ACTIVATION_MANIFEST_BYTES
            or hashlib.sha256(candidate.activation_manifest).hexdigest()
                != candidate.activation_manifest_sha256):
        raise CredentialError("activation manifest bytes or digest are invalid")
    try:
        manifest = json.loads(candidate.activation_manifest.decode("utf-8", errors="strict"))
        payload = json.loads(candidate.policy_payload.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("candidate policy or activation manifest is malformed") from error
    if (canonical_json(manifest) != candidate.activation_manifest
            or canonical_json(payload) != candidate.policy_payload):
        raise CredentialError("candidate policy or activation manifest is not canonical")
    digest = canonical_policy_digest(payload)
    if digest != candidate.policy_digest:
        raise CredentialError("candidate policy digest differs from canonical payload")
    expected_declaration = parse_root_transition_declaration(canonical_json(
        _declaration_document(intent, digest)))
    try:
        checked_declaration = parse_root_transition_declaration(
            canonical_json(asdict(candidate.declaration)))
    except (AttributeError, TypeError, ValueError, SnapshotError) as error:
        raise CredentialError("candidate declaration is malformed") from error
    if (canonical_json(asdict(checked_declaration))
            != canonical_json(asdict(expected_declaration))):
        raise CredentialError("candidate declaration differs from intent and final policy")
    intent_digest = _intent_hash(intent)
    issuance_hash = hashlib.sha256(candidate.issuance_candidate.manifest).hexdigest()
    if (candidate.preparation_intent_sha256 != intent_digest
            or candidate.issuance_manifest_sha256 != issuance_hash):
        raise CredentialError("candidate claimed intent or issuance digest is inconsistent")
    expected_manifest = {
        "domain": ACTIVATION_MANIFEST_DOMAIN, "version": 1,
        "transition_id": intent.transition_id,
        "preparation_intent_sha256": intent_digest,
        "issuance_manifest_sha256": issuance_hash,
        "old_ca_sha256": intent.old_ca_sha256, "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "old_launch_digest": candidate.old_launch_digest,
        "new_launch_digest": candidate.new_launch_digest,
        "old_launch_specs": [role_launch_document(x) for x in old_specs],
        "new_launch_specs": [role_launch_document(x) for x in new_specs],
        "policy_revision": intent.old_policy_revision + 1,
        "policy_digest": digest,
        "policy_payload_sha256": hashlib.sha256(candidate.policy_payload).hexdigest(),
        "new_certificates": [
            {"identity": list(item.identity), "serial": item.record.serial,
             "certificate_sha256": item.record.certificate_sha256,
             "public_key_sha256": item.record.public_key_sha256}
            for item in issued],
    }
    if canonical_json(manifest) != canonical_json(expected_manifest):
        raise CredentialError("activation manifest does not bind the prepared candidate")
    if (type(payload) is not dict
            or type(payload.get("revision")) is not int
            or type(payload.get("issued_at")) is not int
            or type(payload.get("expires_at")) is not int
            or payload.get("revision") != intent.old_policy_revision + 1
            or payload.get("issued_at") > sample.earliest_wall
            or payload.get("expires_at") > intent.overlap_not_after
            or payload.get("expires_at") > int(new_ca.not_valid_after_utc.timestamp())
            or payload.get("expires_at") <= sample.latest_wall
            or payload.get("expires_at") - payload.get("issued_at") > MAX_SNAPSHOT_LIFETIME_SECONDS):
        raise CredentialError("candidate policy time or revision bounds are invalid")
    expected_credentials = sorted((_record_document(item.record) for item in issued),
                                 key=lambda item: (item["account_id"], item["device_id"], item["role"]))
    if payload.get("credentials") != expected_credentials:
        raise CredentialError("candidate policy credentials differ from issued certificate cohort")
    new_store = SnapshotStore(
        verification_key_pem=new_snapshot_public_key_pem,
        ca_certificate_pem=new_ca_certificate_pem, clock=clock,
        minimum_revision=intent.old_policy_revision + 1,
        minimum_policy_digest=digest)
    try:
        new_view = new_store.install(candidate.signed_snapshot)
    except SnapshotError as error:
        raise CredentialError("candidate signed policy is invalid") from error
    if new_view.canonical_payload != candidate.policy_payload:
        raise CredentialError("signed candidate snapshot differs from canonical policy payload")
    _validate_policy_grants(old_view, new_view, intent, issued, new_specs, sample)
    final_sample = clock.sample()
    _assert_overlap(intent, final_sample)
    final_old_view, final_old_records = _check_old_policy(intent, old_snapshot_store, final_sample)
    if final_old_view.policy_digest != old_view.policy_digest or final_old_records != old_records:
        raise CredentialError("old policy or credentials changed during candidate validation")
    final_new_view = new_store.current(sample=final_sample)
    for record in final_new_view.credentials_by_serial.values():
        new_store.assert_credential_live(final_new_view, record, final_sample)
    _validate_policy_grants(old_view, final_new_view, intent, issued, new_specs, final_sample)
    return candidate.declaration


def build_final_activation_candidate(
        *, intent: PreparationIntent,
        issuance_candidate: RootTransitionIssuanceCandidate,
        old_snapshot_store: SnapshotStore,
        old_launch_specs: Sequence[RoleLaunchSpec],
        new_launch_specs: Sequence[RoleLaunchSpec],
        new_ca_certificate_pem: bytes,
        new_snapshot_signing_key_pem: bytes,
        new_csr_by_identity: dict,
        requested_expires_at: int,
        retained_old_grants: Sequence[Grant] | None = None) -> PreparedActivationCandidate:
    """Prepare signed policy and immutable launch manifest; never activates."""
    if type(intent) is not PreparationIntent:
        raise CredentialError("activation candidate requires a preparation intent")
    if type(requested_expires_at) is not int:
        raise CredentialError("requested policy expiry must be an exact integer")
    clock = old_snapshot_store.clock
    sample = clock.sample()
    _assert_overlap(intent, sample)
    if requested_expires_at <= sample.latest_wall:
        raise CredentialError("requested policy expiry is not conservatively in the future")
    issued_at = int(sample.earliest_wall)
    if requested_expires_at - issued_at > MAX_SNAPSHOT_LIFETIME_SECONDS:
        raise CredentialError("new policy lifetime exceeds 300 seconds")
    issued = _revalidate_issuance(intent, issuance_candidate,
                                  new_ca_certificate_pem, sample)
    _validate_csr_bindings(intent, issued, new_csr_by_identity)
    old_view, _ = _check_old_policy(intent, old_snapshot_store, sample)
    old_specs, new_specs, old_map, new_map = _normalize_launches(
        intent, issued, old_launch_specs, new_launch_specs)
    new_ca = verify_ca(new_ca_certificate_pem, now=sample.wall,
                       uncertainty_seconds=sample.uncertainty)
    new_signer_private = _key(new_snapshot_signing_key_pem)
    new_signer_public = new_signer_private.public_key()
    if public_key_sha256(new_signer_public) != intent.new_snapshot_key_sha256:
        raise CredentialError("new snapshot signing key differs from preparation pin")
    _check_authority_separation(intent, old_snapshot_store, new_ca,
                                new_signer_public, old_view, issued, sample)
    if len(set(record.record.serial for record in issued)) != len(issued):
        raise CredentialError("issued cohort contains duplicate serials")
    issued_map = {item.identity: item.record for item in issued}
    policy_expires = min(requested_expires_at, intent.overlap_not_after)
    # Keep the caller's exact requested expiry as the snapshot bound; a request
    # beyond the overlap is rejected rather than silently extended or rewritten.
    if requested_expires_at > intent.overlap_not_after:
        raise CredentialError("requested policy expiry exceeds transition overlap")
    grants = _policy_grants(old_view, sample, old_map, new_map, issued_map,
                            retained_old_grants, intent, policy_expires)
    credentials = sorted((_record_document(item.record) for item in issued),
                         key=lambda item: (item["account_id"], item["device_id"], item["role"]))
    payload = {
        "version": 1, "revision": intent.old_policy_revision + 1,
        "issued_at": issued_at, "expires_at": policy_expires,
        "revoked_serials": [], "revoked_devices": [],
        "credentials": credentials,
        "grants": [_grant_document(item) for item in grants],
    }
    policy_digest = canonical_policy_digest(payload)
    declaration = parse_root_transition_declaration(canonical_json(
        _declaration_document(intent, policy_digest)))
    intent_digest = _intent_hash(intent)
    issuance_hash = hashlib.sha256(issuance_candidate.manifest).hexdigest()
    old_launch_digest = _launch_digest(old_specs)
    new_launch_digest = _launch_digest(new_specs)
    manifest = canonical_json({
        "domain": ACTIVATION_MANIFEST_DOMAIN, "version": 1,
        "transition_id": intent.transition_id,
        "preparation_intent_sha256": intent_digest,
        "issuance_manifest_sha256": issuance_hash,
        "old_ca_sha256": intent.old_ca_sha256,
        "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "old_launch_digest": old_launch_digest,
        "new_launch_digest": new_launch_digest,
        "old_launch_specs": [role_launch_document(item) for item in old_specs],
        "new_launch_specs": [role_launch_document(item) for item in new_specs],
        "policy_revision": payload["revision"],
        "policy_digest": policy_digest,
        "policy_payload_sha256": hashlib.sha256(canonical_json(payload)).hexdigest(),
        "new_certificates": [
            {"identity": list(item.identity), "serial": item.record.serial,
             "certificate_sha256": item.record.certificate_sha256,
             "public_key_sha256": item.record.public_key_sha256}
            for item in issued],
    })
    if len(manifest) > MAX_ACTIVATION_MANIFEST_BYTES:
        raise CredentialError("activation manifest exceeds its 64 KiB bound")
    if requested_expires_at > int(new_ca.not_valid_after_utc.timestamp()):
        raise CredentialError("new policy expiry exceeds the pinned new CA validity")
    signed_snapshot = sign_snapshot(payload, new_snapshot_signing_key_pem)
    new_store = SnapshotStore(
        verification_key_pem=new_signer_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        ca_certificate_pem=new_ca_certificate_pem, clock=clock,
        minimum_revision=intent.old_policy_revision + 1,
        minimum_policy_digest=policy_digest)
    view = new_store.install(signed_snapshot)
    if view.policy_digest != policy_digest:
        raise CredentialError("new signed snapshot digest changed during verification")
    final_sample = clock.sample()
    _assert_overlap(intent, final_sample)
    current_old, _ = _check_old_policy(intent, old_snapshot_store, final_sample)
    if current_old.policy_digest != old_view.policy_digest:
        raise CredentialError("old policy changed while preparing activation candidate")
    final_view = new_store.current(sample=final_sample)
    for serial, record in final_view.credentials_by_serial.items():
        new_store.assert_credential_live(final_view, record, final_sample)
    if final_view.expires_at <= final_sample.latest_wall:
        raise CredentialError("prepared snapshot expired before candidate return")
    return PreparedActivationCandidate(
        intent.transition_id, intent_digest, issuance_hash,
        hashlib.sha256(manifest).hexdigest(), old_launch_digest,
        new_launch_digest, old_specs, new_specs, declaration, policy_digest,
        canonical_json(payload), signed_snapshot, issuance_candidate, manifest)

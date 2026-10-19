"""Bounded validation of a selected C2 multi-host root cohort.

This is a read_selected validation callback foundation. It creates no identity,
runtime binding, admission, claim, process, or readiness authority.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization

from .certificates import _pem_certificate, certificate_sha256, public_key_sha256, verify_ca
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError, StorageError
from .root_c2_group_scope import (MAX_SCOPE_BYTES, C2HostGroupScope,
    parse_c2_host_group_scope_bytes, validate_c2_scope_expectations)
from .root_transition_launch import (RoleLaunchSpec, canonical_role_launch_digest,
    parse_role_launch_spec, role_launch_document)
from .root_transition_storage import (MAX_ARTIFACT_BYTES, MAX_ARTIFACT_TOTAL_BYTES,
    MAX_ARTIFACTS, MAX_POLICY_BYTES, RootGenerationSelector,
    _authenticate_policy_snapshot, root_generation_selector_document,
    parse_root_generation_selector)
from .snapshot import SnapshotStore, canonical_policy_digest

C2_ACTIVATION_MANIFEST_DOMAIN = "steamboat-root-c2-activation-v1"
MAX_MANIFEST_BYTES = MAX_ARTIFACT_BYTES
_MANIFEST_FIELDS = frozenset({
    "domain", "version", "transition_id", "preparation_intent_sha256",
    "issuance_manifest_sha256", "old_ca_sha256", "new_ca_sha256",
    "old_snapshot_key_sha256", "new_snapshot_key_sha256", "old_launch_digest",
    "new_launch_digest", "old_launch_specs", "new_launch_specs", "policy_revision",
    "policy_digest", "policy_payload_sha256", "new_certificates",
    "old_host_group_scopes", "new_host_group_scopes",
})


@dataclass(frozen=True)
class C2SelectedCohort:
    old_specs: tuple[RoleLaunchSpec, ...]
    new_specs: tuple[RoleLaunchSpec, ...]
    old_groups: tuple[C2HostGroupScope, ...]
    new_groups: tuple[C2HostGroupScope, ...]
    generation_sha256: str
    selector_sha256: str
    activation_manifest_sha256: str
    policy_revision: int
    policy_digest: str
    active_policy_snapshot_sha256: str

    def to_document(self) -> dict:
        return {
            "generation_sha256": self.generation_sha256,
            "selector_sha256": self.selector_sha256,
            "activation_manifest_sha256": self.activation_manifest_sha256,
            "policy_revision": self.policy_revision,
            "policy_digest": self.policy_digest,
            "active_policy_snapshot_sha256": self.active_policy_snapshot_sha256,
            "old_launch_specs": [role_launch_document(x) for x in self.old_specs],
            "new_launch_specs": [role_launch_document(x) for x in self.new_specs],
            "old_host_group_scopes": [x.to_document() for x in self.old_groups],
            "new_host_group_scopes": [x.to_document() for x in self.new_groups],
        }


def _hash(value, label):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise CredentialError(f"C2 {label} must be lowercase SHA-256 hex")
    return value


def _closed_specs(raw, name):
    if type(raw) is not list or not 1 <= len(raw) <= 16:
        raise CredentialError(f"C2 {name} must contain one to sixteen launch roles")
    try:
        specs = tuple(parse_role_launch_spec(x) for x in raw)
        canonical_role_launch_digest(specs)
    except (BindingError, TypeError, ValueError) as error:
        raise CredentialError(f"C2 {name} is invalid") from error
    return specs


def _groups(raw, name):
    if type(raw) is not list or len(raw) > 16:
        raise CredentialError(f"C2 {name} exceeds its host-group bound")
    groups = []
    total = 0
    previous = None
    for item in raw:
        encoded = canonical_json(item)
        total += len(encoded)
        if len(encoded) > MAX_SCOPE_BYTES or total > MAX_SCOPE_BYTES:
            raise CredentialError(f"C2 {name} exceeds its 16 KiB scope bound")
        try:
            group = parse_c2_host_group_scope_bytes(encoded)
        except SnapshotError as error:
            raise CredentialError(f"C2 {name} contains an invalid scope") from error
        key = (group.account_id, group.device_id, group.role)
        if previous is not None and key <= previous:
            raise CredentialError(f"C2 {name} must be sorted and unique")
        previous = key
        groups.append(group)
    return tuple(groups)


def _bind_groups(groups, specs, generation):
    by_identity = {x.identity: x for x in specs}
    if len(groups) > sum(x.role == "host" for x in specs):
        raise CredentialError("C2 host group count exceeds declared host roles")
    for group in groups:
        spec = by_identity.get((group.account_id, group.device_id, "host"))
        if spec is None or group.generation_sha256 != generation:
            raise CredentialError("C2 host group has no matching launch role or generation")
        try:
            validate_c2_scope_expectations(group,
                account_id=spec.account_id, device_id=spec.device_id,
                credential_serial=spec.serial, credential_epoch=spec.credential_epoch,
                certificate_sha256=spec.certificate_sha256,
                public_key_sha256=spec.public_key_sha256, parent_boot_id=spec.boot_id,
                generation_sha256=generation, admission_epoch=spec.admission_epoch)
        except SnapshotError as error:
            raise CredentialError("C2 host group differs from its launch role") from error
    return { (g.account_id, g.device_id, g.role): g for g in groups }


def _validate_grants(view, specs, groups, sample):
    spec_by_identity = {x.identity: x for x in specs}
    for spec in specs:
        record = view.credential(spec.serial)
        if (record is None or record.identity != spec.identity
                or record.credential_epoch != spec.credential_epoch
                or record.certificate_sha256 != spec.certificate_sha256
                or record.public_key_sha256 != spec.public_key_sha256):
            raise CredentialError("C2 launch credential differs from active signed policy")
    for grant in view.grants:
        if (sample.latest_wall >= grant.not_after
                or sample.monotonic >= view.grant_deadlines[grant.identity]):
            continue
        target_identity = (grant.target_account_id, grant.target_device_id, grant.target_role)
        target = spec_by_identity.get(target_identity)
        actor = spec_by_identity.get((grant.account_id, grant.device_id, grant.role))
        if target is None and actor is None:
            continue
        if actor is None or target is None:
            raise CredentialError("C2 selected cohort has an active grant outside its declared roles")
        if (grant.actor_boot_id is not None and grant.actor_boot_id != actor.boot_id
                or grant.actor_serial != actor.serial
                or grant.actor_public_key_sha256 != actor.public_key_sha256
                or grant.actor_credential_epoch != actor.credential_epoch):
            raise CredentialError("C2 active grant actor differs from selected parent role")
        group = groups.get(target.identity)
        if group is None:
            if (grant.target_boot_id != target.boot_id or
                    grant.target_serial != target.serial or
                    grant.target_credential_epoch != target.credential_epoch or
                    grant.target_public_key_sha256 != target.public_key_sha256):
                raise CredentialError("C2 active grant differs from a singular selected target")
            continue
        component = next((x for x in group.components
                          if x.worker_boot_id == grant.target_boot_id
                          and x.assignment_id == grant.assignment_id), None)
        if component is None:
            raise CredentialError("C2 active grant escapes the declared component tuple")
        if grant.model_id != group.model_id:
            raise CredentialError("C2 component grant model differs from selected host group")
        if (grant.target_serial != group.credential.serial
                or grant.target_credential_epoch != group.credential.credential_epoch
                or grant.target_public_key_sha256 != group.credential.public_key_sha256
                or (grant.target_serial, grant.target_credential_epoch,
                    grant.target_public_key_sha256) !=
                   (target.serial, target.credential_epoch, target.public_key_sha256)):
            raise CredentialError("C2 component grant credential differs from selected host")
        if grant.actor_boot_id is not None and grant.actor_boot_id != actor.boot_id:
            raise CredentialError("C2 host-group worker cannot act as an actor")


def validate_c2_selected_cohort(selector, bundle, active_policy, *, clock: Clock) -> C2SelectedCohort:
    """Parse and validate bytes supplied to a read_selected validation callback.

    Caller must use this only as that store's callback; this does not verify disk
    provenance independently or authorize a process to start.
    """
    if type(clock) is not Clock or type(selector) is not RootGenerationSelector:
        raise CredentialError("C2 selected validation requires trusted exact inputs")
    if type(bundle) is not dict or len(bundle) > MAX_ARTIFACTS:
        raise CredentialError("C2 selected artifact bundle exceeds its count bound")
    total = 0
    for name, data in bundle.items():
        if type(data) is not bytes or not 1 <= len(data) <= MAX_ARTIFACT_BYTES:
            raise CredentialError("C2 selected artifact has invalid bytes or size")
        total += len(data)
    if total > MAX_ARTIFACT_TOTAL_BYTES:
        raise CredentialError("C2 selected artifact bundle exceeds its total bound")
    try:
        selector_bytes = canonical_json(root_generation_selector_document(selector))
        checked_selector = parse_root_generation_selector(selector_bytes)
    except (StorageError, TypeError, ValueError) as error:
        raise CredentialError("C2 selected selector is malformed") from error
    if dict(checked_selector.artifact_sha256) != {k: hashlib.sha256(v).hexdigest()
                                                  for k, v in bundle.items()}:
        raise CredentialError("C2 selected artifacts differ from selector hashes")
    manifest_bytes = bundle.get("activation_manifest.json")
    if (manifest_bytes is None or len(manifest_bytes) > MAX_MANIFEST_BYTES
            or hashlib.sha256(manifest_bytes).hexdigest() != selector.activation_manifest_sha256):
        raise CredentialError("C2 activation manifest hash differs from selected selector")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("C2 activation manifest is malformed") from error
    if (type(manifest) is not dict or set(manifest) != _MANIFEST_FIELDS
            or manifest.get("domain") != C2_ACTIVATION_MANIFEST_DOMAIN
            or type(manifest.get("version")) is not int or manifest["version"] != 1
            or canonical_json(manifest) != manifest_bytes):
        raise CredentialError("C2 activation manifest is not closed canonical version 1")
    for name in ("preparation_intent_sha256", "issuance_manifest_sha256", "old_ca_sha256",
                 "new_ca_sha256", "old_snapshot_key_sha256", "new_snapshot_key_sha256",
                 "old_launch_digest", "new_launch_digest", "policy_digest",
                 "policy_payload_sha256"):
        _hash(manifest[name], f"manifest {name}")
    if type(manifest["policy_revision"]) is not int or manifest["policy_revision"] < 1:
        raise CredentialError("C2 manifest policy revision is invalid")
    old_specs = _closed_specs(manifest["old_launch_specs"], "old launch specs")
    new_specs = _closed_specs(manifest["new_launch_specs"], "new launch specs")
    if {x.identity for x in old_specs} != {x.identity for x in new_specs}:
        raise CredentialError("C2 old and new launch plans must cover identical role identities")
    old_generations = {x.generation_sha256 for x in old_specs}
    if len(old_generations) != 1 or selector.generation_sha256 in old_generations:
        raise CredentialError("C2 old launch roles must share a generation distinct from selected")
    old_by_identity = {x.identity: x for x in old_specs}
    for spec in new_specs:
        before = old_by_identity[spec.identity]
        if (spec.credential_epoch != before.credential_epoch + 1
                or spec.admission_epoch != before.admission_epoch + 1):
            raise CredentialError("C2 launch credential and admission epochs must advance by one")
    for label, specs, artifact, digest_name in (
            ("old", old_specs, "old_launch_specs.json", "old_launch_digest"),
            ("new", new_specs, "new_launch_specs.json", "new_launch_digest")):
        doc = [role_launch_document(x) for x in specs]
        encoded = canonical_json(doc)
        if (bundle.get(artifact) != encoded or canonical_role_launch_digest(specs) !=
                _hash(manifest[digest_name], f"{label} launch digest")):
            raise CredentialError(f"C2 {label} launch artifact or digest differs from manifest")
    if any(x.generation_sha256 != selector.generation_sha256 for x in new_specs):
        raise CredentialError("C2 new launch generation differs from selected selector")
    old_groups = _groups(manifest["old_host_group_scopes"], "old host groups")
    new_groups = _groups(manifest["new_host_group_scopes"], "new host groups")
    _bind_groups(old_groups, old_specs, old_specs[0].generation_sha256)
    new_map = _bind_groups(new_groups, new_specs, selector.generation_sha256)
    new_host_ids = {x.identity for x in new_specs if x.role == "host"}
    if set(new_map) != new_host_ids:
        raise CredentialError("C2 selected cohort must scope every declared host role")
    old_boot_list = [x.boot_id for x in old_specs] + [
        c.worker_boot_id for g in old_groups for c in g.components]
    if len(old_boot_list) != len(set(old_boot_list)):
        raise CredentialError("C2 previous cohort repeats a parent or child boot ID")
    old_boots = set(old_boot_list)
    new_boots = [x.boot_id for x in new_specs] + [c.worker_boot_id for g in new_groups for c in g.components]
    if len(new_boots) != len(set(new_boots)) or old_boots.intersection(new_boots):
        raise CredentialError("C2 selected cohort reuses parent or child boot IDs")
    expected_certs = [{"identity": list(x.identity), "serial": x.serial,
        "certificate_sha256": x.certificate_sha256, "public_key_sha256": x.public_key_sha256}
        for x in new_specs]
    if canonical_json(manifest["new_certificates"]) != canonical_json(expected_certs):
        raise CredentialError("C2 new certificate pins differ from launch specs")
    try:
        ca = _pem_certificate(bundle["ca_certificate.pem"])
        signer = serialization.load_pem_public_key(bundle["snapshot_signer_public.pem"])
        sample = clock.sample()
        verify_ca(bundle["ca_certificate.pem"], now=sample.wall,
                  uncertainty_seconds=sample.uncertainty)
        if (manifest["new_ca_sha256"] != certificate_sha256(ca)
                or manifest["new_snapshot_key_sha256"] != public_key_sha256(signer)):
            raise CredentialError("C2 selected authority pins differ from manifest")
        payload, _baseline_credentials, _baseline_grants = _authenticate_policy_snapshot(
            bundle["policy_snapshot.json"], ca_pem=bundle["ca_certificate.pem"],
            signer_pem=bundle["snapshot_signer_public.pem"], sample=sample)
        if (manifest["policy_revision"] != payload["revision"]
                or manifest["policy_digest"] != canonical_policy_digest(payload)
                or manifest["policy_payload_sha256"] != hashlib.sha256(canonical_json(payload)).hexdigest()):
            raise CredentialError("C2 baseline policy pins differ from manifest")
        if (type(active_policy) is not bytes or not 1 <= len(active_policy) <= MAX_POLICY_BYTES
                or hashlib.sha256(active_policy).hexdigest() !=
                   selector.active_policy_snapshot_sha256):
            raise CredentialError("C2 active policy bytes differ from selector hash")
        if selector.policy_revision < manifest["policy_revision"]:
            raise CredentialError("C2 selected policy revision predates its baseline")
        current_store = SnapshotStore(
            verification_key_pem=bundle["snapshot_signer_public.pem"],
            ca_certificate_pem=bundle["ca_certificate.pem"], clock=clock,
            minimum_revision=selector.policy_revision,
            minimum_policy_digest=selector.policy_digest)
        current_store.install(active_policy)
        sample = clock.sample()
        view = current_store.current(sample=sample)
        if view.revision != selector.policy_revision or view.policy_digest != selector.policy_digest:
            raise CredentialError("C2 active policy is not the selected current head")
    except CredentialError:
        raise
    except (KeyError, UnicodeError, ValueError, TypeError, SnapshotError, StorageError) as error:
        raise CredentialError("C2 selected policy or authority validation failed") from error
    _validate_grants(view, new_specs, new_map, sample)
    return C2SelectedCohort(old_specs, new_specs, old_groups, new_groups,
        selector.generation_sha256, hashlib.sha256(selector_bytes).hexdigest(),
        selector.activation_manifest_sha256, selector.policy_revision,
        selector.policy_digest, selector.active_policy_snapshot_sha256)


def make_c2_selected_validation_callback(*, clock: Clock, capture: dict):
    """Create a RootGenerationStore callback that captures the validated view.

    ``read_selected`` requires callbacks to return ``None``. The returned
    function therefore stores the inert result under ``capture['cohort']`` and
    returns exactly ``None`` after validation succeeds.
    """
    if type(clock) is not Clock or type(capture) is not dict or capture:
        raise TypeError("C2 callback requires an exact Clock and empty result dict")

    def validate(selector, bundle, active_policy):
        capture.clear()
        cohort = validate_c2_selected_cohort(selector, dict(bundle), active_policy,
                                             clock=clock)
        capture["cohort"] = cohort
        return None

    return validate

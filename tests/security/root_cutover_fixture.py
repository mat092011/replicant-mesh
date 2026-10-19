"""Private material builder for the native Linux cold-root-cutover test.

This fixture creates fresh real credentials and protected local files.  It has
no network, Docker, settings, or process side effects; process ownership stays
with the test's RetirementSupervisor instances.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RootCutoverFixture:
    """Build exact old/new protected cohorts from real signed identity APIs."""

    def __init__(self, base: Path, artifact_directory: Path,
                 reference_directory: Path):
        if os.name != "posix" or sys.platform != "linux" or not Path("/proc").is_dir():
            raise RuntimeError("root cutover fixture requires native Linux and /proc")
        self.base = Path(base).resolve()
        self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.base, 0o700)
        self.artifact_directory = Path(artifact_directory).resolve(strict=True)
        self.reference_directory = Path(reference_directory).resolve(strict=True)
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot
        from steamboat_security import Clock, SnapshotStore
        from steamboat_security.certificates import (
            _pem_certificate, certificate_sha256, generate_ca,
            generate_private_key_pem, make_csr, public_key_sha256,
        )
        from steamboat_security.operator import (
            generate_authorization_signing_key_pem,
            snapshot_public_key_pem,
        )
        from steamboat_security.root_transition import AffectedPrincipal
        from steamboat_security.root_transition_issuance import (
            PrincipalIssuanceInput, prepare_root_transition_issuance,
        )
        from steamboat_security.root_transition_policy import (
            build_final_activation_candidate, expected_transition_generation_sha256,
        )
        from steamboat_security.root_transition_preparation import (
            PREPARATION_PURPOSE, make_preparation_possession_proof,
            parse_preparation_intent,
        )
        from steamboat_security.root_transition_proof import make_old_role_key_possession_proof
        from steamboat_security.root_transition_final_approval import (
            FINAL_APPROVAL_PURPOSE, FinalActivationApproval,
            FinalApprovalPrincipalInput, final_activation_approval_document,
        )
        from steamboat_security.root_transition_launch import (
            RoleLaunchSpec, canonical_role_launch_digest, role_launch_document,
        )
        from steamboat_security.codec import canonical_json
        from cryptography.hazmat.primitives import serialization
        from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture

        manifest = load_manifest(self.artifact_directory)
        verify_snapshot(self.reference_directory)
        self.manifest = manifest
        self.fingerprint = manifest["fingerprint"]
        self.clock = Clock.system(uncertainty_seconds=lambda: 0.5)
        self.identities = SecurePipelineIdentityFixture(
            self.fingerprint, clock_uncertainty_seconds=0.5,
            leaf_lifetime_seconds=300)
        self.old_store = SnapshotStore(
            verification_key_pem=self.identities.snapshot_verification_key_pem,
            ca_certificate_pem=self.identities.cohort_ca_pem, clock=self.clock)
        self.old_store.install(self.identities.signed_snapshot)
        old_view = self.old_store.current()
        old_sample = self.clock.sample()
        for principal in self.identities.principals.values():
            credential = old_view.credentials_by_serial[principal.record["serial"]]
            remaining = credential.not_after - old_sample.latest_wall
            if not 0 < remaining <= 300:
                raise RuntimeError("cold-cutover old leaf is outside the real renewal window")
        self.now = int(self.clock.sample().wall)
        self.old_generation = hashlib.sha256(b"cold-cutover-old-generation").hexdigest()
        self.transition_id = secrets.token_hex(16)
        self.new_ca, self.new_ca_key = generate_ca(common_name="cold cutover new cohort",
                                                    now=self.now - 60, lifetime_days=2)
        self.new_snapshot_key = generate_authorization_signing_key_pem()
        self.new_snapshot_public = snapshot_public_key_pem(self.new_snapshot_key)

        role_names = ("worker-1", "worker-2", "worker-3", "coordinator", "consumer")
        self.role_by_name = {name: self.identities.principals[name] for name in role_names}
        self.roles = []
        self.new_keys = {}
        self.new_csrs = {}
        affected = []
        for name in role_names:
            old = self.role_by_name[name]
            new_key = generate_private_key_pem()
            csr = make_csr(new_key, account_id=old.account_id,
                           device_id=old.device_id, role=old.role,
                           ip_sans=("127.0.0.1",))
            old_record = old.record
            principal = AffectedPrincipal(
                old.account_id, old.device_id, old.role, old.boot_id,
                old_record["serial"], old_record["certificate_sha256"],
                old_record["public_key_sha256"], old_record["credential_epoch"],
                3, _sha(csr), (), ("127.0.0.1",))
            self.roles.append({"name": name, "old": old, "principal": principal,
                               "new_key": new_key, "new_csr": csr})
            self.new_keys[principal.identity] = new_key
            self.new_csrs[principal.identity] = csr
            affected.append(principal)
        affected.sort(key=lambda item: item.identity)
        old_public_key_hash = public_key_sha256(serialization.load_pem_public_key(
            self.identities.snapshot_verification_key_pem))
        intent_doc = {
            "purpose": PREPARATION_PURPOSE, "schema_version": 1,
            "transition_id": self.transition_id,
            "old_ca_sha256": certificate_sha256(_pem_certificate(
                self.identities.cohort_ca_pem)),
            "new_ca_sha256": certificate_sha256(_pem_certificate(self.new_ca)),
            "old_snapshot_key_sha256": old_public_key_hash,
            "new_snapshot_key_sha256": public_key_sha256(serialization.load_pem_private_key(
                self.new_snapshot_key, password=None).public_key()),
            "overlap_not_before": self.now - 1,
            "overlap_not_after": self.now + 250,
            "old_policy_revision": old_view.revision,
            "old_policy_digest": old_view.policy_digest,
            "next_minimum_revision": old_view.revision + 1,
            "affected_principals": [{
                "account_id": p.account_id, "device_id": p.device_id,
                "role": p.role, "old_boot_id": p.old_boot_id,
                "old_serial": p.old_serial,
                "old_certificate_sha256": p.old_certificate_sha256,
                "old_public_key_sha256": p.old_public_key_sha256,
                "old_credential_epoch": p.old_credential_epoch,
                "old_admission_epoch": p.old_admission_epoch,
                "new_csr_sha256": p.new_csr_sha256,
                "dns_sans": list(p.dns_sans), "ip_sans": list(p.ip_sans),
            } for p in affected],
        }
        self.preparation = self.base / "preparation"
        self.approval_root = self.base / "approval"
        for root in (self.preparation, self.approval_root):
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
        self.preparation_path = self.preparation / "intent.json"
        self.preparation_bytes = canonical_json(intent_doc)
        self.preparation_path.write_bytes(self.preparation_bytes)
        os.chmod(self.preparation_path, 0o600)
        self.intent = parse_preparation_intent(self.preparation_bytes)

        issuance_inputs = []
        by_identity = {item.identity: item for item in self.intent.affected_principals}
        for role in self.roles:
            old, principal = role["old"], by_identity[(role["old"].account_id,
                                                     role["old"].device_id,
                                                     role["old"].role)]
            proof = make_preparation_possession_proof(
                self.intent, principal, old_private_key_pem=old.private_key_pem,
                old_certificate_pem=old.certificate_pem, new_csr_pem=role["new_csr"])
            issuance_inputs.append(PrincipalIssuanceInput(
                principal, old.certificate_pem, role["new_csr"], proof))
        self.issuance = prepare_root_transition_issuance(
            approval_path=self.preparation_path, approval_root=self.preparation,
            expected_uid=os.geteuid(), clock=self.clock,
            old_snapshot_store=self.old_store,
            new_ca_certificate_pem=self.new_ca,
            new_ca_private_key_pem=self.new_ca_key,
            new_snapshot_public_key_pem=self.new_snapshot_public,
            principal_inputs=tuple(issuance_inputs))
        self.issued_by_identity = {item.identity: item for item in self.issuance.principals}
        self.new_generation = expected_transition_generation_sha256(self.intent)
        self.new_root = self.base / "selected-root"
        self.claim_root = self.base / "claims"
        self.claim_root.mkdir(mode=0o700)
        os.chmod(self.claim_root, 0o700)
        self.old_generation_material = self._write_role_cohort("old", self.old_generation)
        self.new_generation_material = self._write_role_cohort("new", self.new_generation)
        self.old_specs = self.old_generation_material["specs"]
        self.new_specs = self.new_generation_material["specs"]
        self.candidate = build_final_activation_candidate(
            intent=self.intent, issuance_candidate=self.issuance,
            old_snapshot_store=self.old_store, old_launch_specs=self.old_specs,
            new_launch_specs=self.new_specs,
            new_ca_certificate_pem=self.new_ca,
            new_snapshot_signing_key_pem=self.new_snapshot_key,
            new_csr_by_identity=self.new_csrs,
            requested_expires_at=self.now + 180)
        self._provision_initial_selected()
        final_by_identity = {
            item.identity: item for item in self.candidate.declaration.affected_principals
        }
        self.final_inputs = tuple(FinalApprovalPrincipalInput(
            final_by_identity[role["principal"].identity], role["old"].certificate_pem,
            role["new_csr"], make_old_role_key_possession_proof(
                self.candidate.declaration,
                final_by_identity[role["principal"].identity],
                old_private_key_pem=role["old"].private_key_pem,
                old_certificate_pem=role["old"].certificate_pem,
                new_csr_pem=role["new_csr"])) for role in self.roles)
        approval = FinalActivationApproval(
            1, FINAL_APPROVAL_PURPOSE, self.transition_id,
            self.candidate.preparation_intent_sha256,
            self.candidate.issuance_manifest_sha256,
            self.candidate.activation_manifest_sha256,
            self.candidate.declaration)
        self.approval_path = self.approval_root / "approval.json"
        self.approval_bytes = canonical_json(final_activation_approval_document(approval))
        self.approval_path.write_bytes(self.approval_bytes)
        os.chmod(self.approval_path, 0o600)

    def _write_role_cohort(self, label: str, generation: str):
        from steamboat_security.codec import canonical_json
        from steamboat_security.root_transition_launch import RoleLaunchSpec

        role_root = self.base / f"{label}-roles"
        role_root.mkdir(mode=0o700)
        os.chmod(role_root, 0o700)
        entries = {}
        endpoints = {name: _port() for name in ("worker-1", "worker-2", "worker-3")}
        coordinator_port = _port()
        role_boots = {}
        for role in self.roles:
            old = role["old"]
            role_boots[role["name"]] = old.boot_id if label == "old" else secrets.token_hex(16)
        for role in self.roles:
            name = role["name"]
            principal = role["principal"]
            old = role["old"]
            if label == "old":
                cert, key, record = old.certificate_pem, old.private_key_pem, old.record
                epoch = record["credential_epoch"]
                boot = old.boot_id
                admission = 3
            else:
                issued = self.issued_by_identity[principal.identity]
                cert, key, record = issued.certificate_pem, role["new_key"], {
                    "serial": issued.record.serial,
                    "certificate_sha256": issued.record.certificate_sha256,
                    "public_key_sha256": issued.record.public_key_sha256,
                    "credential_epoch": issued.record.credential_epoch,
                }
                epoch = record["credential_epoch"]
                boot = role_boots[name]
                admission = principal.old_admission_epoch + 1
            root = role_root / name
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            cert_path, key_path = root / "leaf.pem", root / "role-key.pem"
            cert_path.write_bytes(cert); key_path.write_bytes(key)
            os.chmod(cert_path, 0o600); os.chmod(key_path, 0o600)
            nonce = secrets.token_hex(16)
            runtime_path = root / "runtime.json"
            assignment = old.assignment_id
            if name.startswith("worker-"):
                import lab.secure_worker_config as wc
                runtime = {
                    "schema_version": 1, "protected_root": str(root),
                    "account_id": old.account_id, "device_id": old.device_id,
                    "boot_id": boot, "assignment_id": assignment,
                    "worker_name": name, "model_id": wc.MODEL_ID,
                    "model_revision": wc.MODEL_REVISION,
                    "manifest_fingerprint": self.fingerprint,
                    "listen_ip": "127.0.0.1", "listen_port": endpoints[name],
                    "clock_uncertainty_seconds": 0.5,
                    "certificate_path": str(cert_path),
                    "private_key_path": str(key_path),
                    "cohort_ca_path": str(root / "cohort-ca.pem"),
                    "snapshot_verification_key_path": str(root / "snapshot-public.pem"),
                    "signed_snapshot_path": str(root / "snapshot.json"),
                    "artifact_directory": str(self.artifact_directory),
                    "acceptor_directory": str(root / "acceptor"),
                    "status_report_path": str(root / "status.json"),
                }
                runtime_bytes = canonical_json(runtime)
                (root / "cohort-ca.pem").write_bytes(
                    self.identities.cohort_ca_pem if label == "old" else self.new_ca)
                (root / "snapshot-public.pem").write_bytes(
                    self.identities.snapshot_verification_key_pem if label == "old"
                    else self.new_snapshot_public)
                (root / "snapshot.json").write_bytes(
                    self.identities.signed_snapshot if label == "old" else b"pending candidate\n")
                for path in (root / "cohort-ca.pem", root / "snapshot-public.pem",
                             root / "snapshot.json"):
                    os.chmod(path, 0o600)
                (root / "acceptor").mkdir(mode=0o700)
                (root / "status.json").touch(mode=0o600)
                os.chmod(root / "status.json", 0o600)
            elif name == "coordinator":
                observer_path = root / "worker-binding-observations.jsonl"
                observer_path.touch(mode=0o600)
                os.chmod(observer_path, 0o600)
                workers = []
                for index in (1, 2, 3):
                    worker = self.role_by_name[f"worker-{index}"]
                    if label == "old":
                        worker_cert = worker.certificate_pem
                    else:
                        worker_cert = self.issued_by_identity[
                            (worker.account_id, worker.device_id, worker.role)].certificate_pem
                    # The coordinator config requires peer certificate material
                    # to remain inside its own protected root. Copy only the
                    # public leaf; each worker's private credential stays local.
                    cert_path_worker = root / f"worker-{index}-peer-leaf.pem"
                    cert_path_worker.write_bytes(worker_cert)
                    os.chmod(cert_path_worker, 0o600)
                    workers.append({
                        "worker_name": f"worker-{index}",
                        "account_id": worker.account_id, "device_id": worker.device_id,
                        "boot_id": role_boots[f"worker-{index}"],
                        "assignment_id": worker.assignment_id,
                        "certificate_path": str(cert_path_worker),
                        "ip": "127.0.0.1", "port": endpoints[f"worker-{index}"],
                    })
                runtime = {
                    "schema_version": 1, "profile": "native_posix_root_coordinator_v1",
                    "artifact_directory": str(self.artifact_directory),
                    "reference_directory": str(self.reference_directory),
                    "listen_ip": "127.0.0.1", "listen_port": coordinator_port,
                    "clock_uncertainty_seconds": 0.5,
                    "acceptor_directory": str(root / "acceptor"),
                    "status_report_path": str(root / "status.json"),
                    "workers": workers,
                }
                runtime_bytes = canonical_json(runtime)
                (root / "acceptor").mkdir(mode=0o700)
                (root / "status.json").touch(mode=0o600)
                os.chmod(root / "status.json", 0o600)
            else:
                runtime_bytes = canonical_json({"test_owned_consumer_binding": 1})
                status_path = root / "consumer-status.json"
                status_path.touch(mode=0o600)
                os.chmod(status_path, 0o600)
            runtime_path.write_bytes(runtime_bytes)
            os.chmod(runtime_path, 0o600)
            header = {
                "schema_version": 1, "profile": "native_posix_root_role_v1",
                "protected_root": str(root), "selected_root": str(self.new_root),
                "account_id": old.account_id, "device_id": old.device_id,
                "role": old.role, "boot_id": boot,
                "credential_epoch": epoch, "admission_epoch": admission,
                "generation_sha256": generation, "launch_nonce": nonce,
                "certificate_path": str(cert_path),
                "private_key_path": str(key_path),
                "model_id": self.fingerprint, "assignment_id": assignment,
                "runtime_configuration_path": str(runtime_path),
                "runtime_configuration_sha256": _sha(runtime_bytes),
            }
            header_path = root / "config.json"
            header_bytes = canonical_json(header)
            header_path.write_bytes(header_bytes)
            os.chmod(header_path, 0o600)
            spec = RoleLaunchSpec(
                generation, old.account_id, old.device_id, old.role,
                record["serial"], record["certificate_sha256"],
                record["public_key_sha256"], epoch, boot, admission,
                _sha(header_bytes), nonce)
            entries[name] = {"root": root, "cert_path": str(cert_path),
                             "runtime_path": str(runtime_path),
                             "header_path": str(header_path), "spec": spec,
                             "endpoint": endpoints.get(name, coordinator_port)}
            if name == "coordinator":
                entries[name]["observer_path"] = str(observer_path)
        specs = tuple(sorted((entry["spec"] for entry in entries.values()),
                             key=lambda item: item.identity))
        for name, entry in entries.items():
            root = entry["root"]
            if name == "consumer":
                script = root / "consumer-binding-child.py"
                source = self._consumer_child_source()
            elif name.startswith("worker-"):
                script = root / "bootstrap.py"
                source = b"import runpy; runpy.run_path('/app/lab/root_worker.py', run_name='__main__')\n"
            else:
                script = root / "bootstrap.py"
                targets = tuple(("127.0.0.1", endpoints[f"worker-{index}"])
                                for index in (1, 2, 3))
                source = self._coordinator_bootstrap_source(
                    targets, observer_path)
            if name == "consumer":
                source = source.replace(
                    b"import asyncio, json, os, sys, time\n",
                    b"import json, os, signal, sys, time\n")
                source = source.replace(
                    b"while True:\n    time.sleep(0.25)\n",
                    b"stopping = False\n"
                    b"def stop(_signum, _frame):\n"
                    b"    global stopping\n"
                    b"    stopping = True\n"
                    b"signal.signal(signal.SIGTERM, stop)\n"
                    b"signal.signal(signal.SIGINT, stop)\n"
                    b"try:\n"
                    b"    while not stopping: time.sleep(0.05)\n"
                    b"finally:\n"
                    b"    store.close()\n"
                    b"    status = header_path.parent / 'consumer-status.json'\n"
                    b"    status.write_bytes(canonical_json({'event':'root_test_consumer_status',"
                    b"'phase':'stopped','shutdown_confirmed':True}) + b'\\n')\n")
            script.write_bytes(source); os.chmod(script, 0o600)
            executable = str(Path(sys.executable).resolve(strict=True))
            argv = [executable, "-I", str(script), "--config", entry["header_path"]]
            launcher = {
                # The strict manifest pins the bootstrap bytes/argv. The
                # coordinator bootstrap embeds the protected observer path in
                # those hashed bytes; no launcher-manifest schema is changed.
                "schema_version": 1, "containment_profile": "trusted_no_escape_v1",
                "executable_path": executable,
                "executable_sha256": _sha(Path(executable).read_bytes()),
                "script_path": str(script), "script_sha256": _sha(source),
                "configuration_path": entry["header_path"],
                "configuration_sha256": _sha(Path(entry["header_path"]).read_bytes()),
                "argv": argv,
            }
            manifest_path = root / "launcher.json"
            manifest_path.write_bytes(canonical_json(launcher))
            os.chmod(manifest_path, 0o600)
            entry["manifest_path"] = str(manifest_path)
        return {"entries": entries, "specs": specs, "generation": generation}

    def _provision_initial_selected(self):
        """Seed only the old trust root needed to exercise real old processes."""
        from steamboat_security.root_transition_storage import (
            RootGenerationSelector, root_generation_selector_document,
        )
        from steamboat_security.codec import canonical_json
        from steamboat_security.snapshot import canonical_policy_digest
        from steamboat_security.certificates import certificate_sha256
        from steamboat_security.operator import public_key_sha256
        from cryptography.hazmat.primitives import serialization
        from steamboat_security.certificates import _pem_certificate
        from steamboat_security.root_transition_launch import (
            canonical_role_launch_digest, role_launch_document,
        )
        from steamboat_security.root_transition_policy import ACTIVATION_MANIFEST_DOMAIN

        self.new_root.mkdir(mode=0o700)
        os.chmod(self.new_root, 0o700)
        generations = self.new_root / "generations"
        policies = self.new_root / "policies"
        generations.mkdir(mode=0o700)
        policies.mkdir(mode=0o700)
        (self.new_root / "transition.lock").touch(mode=0o600)
        os.chmod(self.new_root / "transition.lock", 0o600)
        specs = self.old_specs
        documents = [role_launch_document(item) for item in specs]
        old_ca_hash = certificate_sha256(_pem_certificate(self.identities.cohort_ca_pem))
        old_signer_hash = public_key_sha256(serialization.load_pem_public_key(
            self.identities.snapshot_verification_key_pem))
        policy_payload = json.loads(self.identities.signed_snapshot)["payload"]
        policy_sha = _sha(self.identities.signed_snapshot)
        artifacts = {
            "policy_snapshot.json": self.identities.signed_snapshot,
            "ca_certificate.pem": self.identities.cohort_ca_pem,
            "snapshot_signer_public.pem": self.identities.snapshot_verification_key_pem,
            "issuance_manifest.json": b"{}",
            "final_approval.json": b"{}",
            "preparation_intent.json": self.preparation_bytes,
            "credential_bundle.json": canonical_json({"credentials": []}),
            "public_csr_bundle.json": canonical_json([]),
            "old_possession_proofs.json": canonical_json([]),
            "retirement_receipt.json": canonical_json({"purpose": "initial_test_root"}),
            "old_launch_specs.json": canonical_json(documents),
            "new_launch_specs.json": canonical_json(documents),
        }
        placeholder = {
            "domain": ACTIVATION_MANIFEST_DOMAIN, "version": 1,
            "transition_id": self.transition_id,
            "preparation_intent_sha256": _sha(self.preparation_bytes),
            "issuance_manifest_sha256": _sha(b"{}"),
            "old_ca_sha256": old_ca_hash, "new_ca_sha256": old_ca_hash,
            "old_snapshot_key_sha256": old_signer_hash,
            "new_snapshot_key_sha256": old_signer_hash,
            "old_launch_digest": canonical_role_launch_digest(specs),
            "new_launch_digest": canonical_role_launch_digest(specs),
            "old_launch_specs": documents, "new_launch_specs": documents,
            "policy_revision": self.old_store.current().revision,
            "policy_digest": canonical_policy_digest(policy_payload),
            "policy_payload_sha256": _sha(canonical_json(policy_payload)),
            "new_certificates": [{
                "identity": list(item.identity), "serial": item.serial,
                "certificate_sha256": item.certificate_sha256,
                "public_key_sha256": item.public_key_sha256,
            } for item in specs],
        }
        artifacts["activation_manifest.json"] = canonical_json(placeholder)
        descriptor_hash = _sha(artifacts["activation_manifest.json"])
        selector = RootGenerationSelector(
            self.old_generation, descriptor_hash,
            self.old_store.current().revision,
            canonical_policy_digest(policy_payload), policy_sha,
            {name: _sha(value) for name, value in artifacts.items()})
        policy_file = policies / f"{policy_sha}.json"
        policy_file.write_bytes(self.identities.signed_snapshot)
        os.chmod(policy_file, 0o600)
        generation_path = generations / self.old_generation
        generation_path.mkdir(mode=0o700)
        descriptor = {
            "schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": self.old_generation,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256),
        }
        for name, value in {"descriptor.json": canonical_json(descriptor), **artifacts}.items():
            path = generation_path / name
            path.write_bytes(value)
            os.chmod(path, 0o600)
        selector_path = self.new_root / "selector.json"
        selector_path.write_bytes(canonical_json(root_generation_selector_document(selector)))
        os.chmod(selector_path, 0o600)
        # Workers and the coordinator read the selected root's signed policy
        # from this protected file, which activation replaces atomically.
        for entry in self.new_generation_material["entries"].values():
            if entry["spec"].role == "host":
                policy_copy = Path(entry["root"]) / "snapshot.json"
                policy_copy.write_bytes(self.candidate.signed_snapshot)
                os.chmod(policy_copy, 0o600)

    @staticmethod
    def _consumer_child_source() -> bytes:
        return b'''import asyncio, json, os, sys, time\nfrom pathlib import Path\nsys.path[:0] = ["/app/src", "/app"]\nfrom steamboat_security.codec import canonical_json\nfrom steamboat_security.clock import Clock\nfrom steamboat_security.root_transition_launch import parse_role_launch_spec\nfrom steamboat_security.root_transition_storage import RootGenerationStore\nfrom steamboat_security.root_runtime import load_root_runtime_binding\nfrom steamboat_security.files import safe_read\nheader_path = Path(sys.argv[2]) if len(sys.argv) == 3 and sys.argv[1] == "--config" else None\nif header_path is None: raise SystemExit(2)\nheader = json.loads(safe_read(header_path, root=header_path.parent, expected_uid=os.geteuid(), max_bytes=16384))\nraw = sys.stdin.buffer.readline(16385)\nif not raw.endswith(b"\\n") or len(raw) > 16384: raise SystemExit(3)\nspecs = json.loads(raw)\nif type(specs) is not list or len(specs) != 1: raise SystemExit(4)\nspec = parse_role_launch_spec(specs[0])\nstore = RootGenerationStore(Path(header["selected_root"]), expected_uid=os.geteuid())\nbinding = load_root_runtime_binding(root_store=store, clock=Clock.system(uncertainty_seconds=lambda: 0.5), expected_launch_spec=spec, configuration_path=header_path, configuration_root=header_path.parent, expected_uid=os.geteuid())\nif binding.local_identity.certificate_pem != safe_read(header["certificate_path"], root=header_path.parent, expected_uid=os.geteuid(), max_bytes=65536): raise SystemExit(5)\npacket = canonical_json({"schema_version":1,"event":"root_role_ready","launch_nonce":spec.launch_nonce,"roles":[specs[0]]}) + b"\\n"\nos.write(1, packet)\nwhile True:\n    time.sleep(0.25)\n'''

    @staticmethod
    def _coordinator_bootstrap_source(targets, observer_path) -> bytes:
        """Pin a bounded test-only observer around actual outbound authorization."""
        source = '''import json,os,runpy,socket,stat,sys,sysconfig,threading,time
from pathlib import Path
def _fixed_app_source_profile():
    if os.name!='posix' or sys.platform!='linux' or sys.flags.isolated!=1: raise RuntimeError('fixed isolated Linux profile is required')
    app=Path('/app')
    info=app.lstat()
    readonly=getattr(os,'ST_RDONLY',None)
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or type(readonly) is not int or readonly<=0 or not os.statvfs(app).f_flag&readonly): raise RuntimeError('fixed /app code mount is not read-only')
    directories=(app/'lab',app/'src',app/'src'/'steamboat_security')
    for directory in directories:
        item=directory.lstat()
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode) or not os.statvfs(directory).f_flag&readonly: raise RuntimeError('fixed coordinator code directory is unavailable')
    for source_root in (app/'lab',app/'src'/'steamboat_security'):
        for parent,children,files in os.walk(source_root,topdown=True,followlinks=False):
            parent_path=Path(parent)
            parent_info=parent_path.lstat()
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode) or not os.statvfs(parent_path).f_flag&readonly: raise RuntimeError('fixed coordinator source tree is not immutable')
            for name in tuple(children)+tuple(files):
                child=parent_path/name
                child_info=child.lstat()
                if stat.S_ISLNK(child_info.st_mode) or not (stat.S_ISDIR(child_info.st_mode) or stat.S_ISREG(child_info.st_mode)) or not os.statvfs(child).f_flag&readonly: raise RuntimeError('fixed coordinator source tree is not immutable')
    for path in (app/'lab'/'root_coordinator.py',app/'lab'/'root_coordinator_runtime.py',app/'lab'/'root_coordinator_config.py',app/'src'/'steamboat_security'/'root_runtime.py'):
        item=path.lstat()
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or not os.statvfs(path).f_flag&readonly: raise RuntimeError('fixed coordinator source is unavailable')
    paths=['/app','/app/src']
    for key in ('stdlib','platstdlib','purelib','platlib'):
        value=sysconfig.get_path(key)
        if value and os.path.isabs(value) and value not in paths: paths.append(value)
    native=sysconfig.get_config_var('DESTSHARED')
    if type(native) is str and os.path.isabs(native) and native not in paths: paths.append(native)
    sys.path[:]=paths
_fixed_app_source_profile()
from steamboat_security.codec import METADATA_KEY,WORKER_SERVICE,parse_metadata
from steamboat_security.outbound import OutboundAuthorizer
_observer_path=__OBSERVER_PATH__
_observer_lock=threading.Lock()
_observer_fd=os.open(_observer_path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC)
_observer_stat=os.fstat(_observer_fd)
if (not stat.S_ISREG(_observer_stat.st_mode) or _observer_stat.st_uid!=os.geteuid() or stat.S_IMODE(_observer_stat.st_mode)!=0o600 or _observer_stat.st_size!=0): raise RuntimeError('test observer file is not a fresh protected regular file')
_observer_count=0
_observer_bytes=0
_original_authorize_outbound=OutboundAuthorizer.authorize_outbound
def _recording_authorize_outbound(self,*,service,method,payload,trusted_request_context,peer_certificate_pem):
    global _observer_count,_observer_bytes
    authorization=_original_authorize_outbound(self,service=service,method=method,payload=payload,trusted_request_context=trusted_request_context,peer_certificate_pem=peer_certificate_pem)
    if service!=WORKER_SERVICE: return authorization
    binding=parse_metadata(service,method,((METADATA_KEY,authorization.binding_bytes),))
    row={'service':service,'method':method,**dict(binding.fields)}
    encoded=json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')+b'\\n'
    with _observer_lock:
        current=os.fstat(_observer_fd)
        if _observer_count>=256 or _observer_bytes+len(encoded)>256*1024 or current.st_size!=_observer_bytes: raise RuntimeError('test observer reached or changed its fixed bound')
        view=memoryview(encoded)
        while view:
            written=os.write(_observer_fd,view)
            if written<=0: raise OSError('test observer write was incomplete')
            view=view[written:]
        _observer_count+=1
        _observer_bytes+=len(encoded)
    return authorization
OutboundAuthorizer.authorize_outbound=_recording_authorize_outbound
targets=__TARGETS__
deadline=time.monotonic()+30
while True:
    ready=True
    for target in targets:
        try:
            with socket.create_connection(target,timeout=0.25): pass
        except OSError:
            ready=False; break
    if ready: break
    if time.monotonic() >= deadline: raise SystemExit(6)
    time.sleep(0.05)
runpy.run_path('/app/lab/root_coordinator.py', run_name='__main__')
'''
        return (source.replace("__OBSERVER_PATH__", repr(str(observer_path)))
                .replace("__TARGETS__", repr(tuple(targets))).encode("utf-8"))

    def launch_inputs(self, label: str):
        from steamboat_security.root_transition_startup import RootRoleLaunch
        material = (self.old_generation_material if label == "old"
                    else self.new_generation_material)
        return tuple(RootRoleLaunch(
            entry["spec"], entry["manifest_path"], str(entry["root"]),
            entry["header_path"], str(entry["root"]))
            for _name, entry in sorted(material["entries"].items(),
                                       key=lambda pair: pair[1]["spec"].identity))

    def close(self):
        if getattr(self, "old_store", None) is not None:
            self.old_store = None
        if getattr(self, "identities", None) is not None:
            self.identities.close()
            self.identities = None

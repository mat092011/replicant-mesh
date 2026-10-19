"""Closed-schema and bounded-material tests for C1b owner controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from dataclasses import fields
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import lab.secure_cohort_owner as owner


RUN_ID = "1" * 32
NONCE = "2" * 32
BOOT_ID = "3" * 32
FINGERPRINT = "4" * 64
INITIAL_DIGEST = "5" * 64
ENDPOINT = "10.1.2.3:50061"
_POSIX_SAFE_READ = (os.name == "posix" and hasattr(os, "geteuid")
                    and hasattr(os, "O_NOFOLLOW"))


def expected(profile=owner.PROFILE_C1B_OWNER_DRAIN):
    return owner.OwnerExpectation(
        profile, RUN_ID, NONCE, BOOT_ID, FINGERPRINT, ENDPOINT,
        INITIAL_DIGEST, 7)


def command(profile, sequence, *, command_id=None, digest=None, revision=None):
    exp = expected(profile)
    if profile == owner.PROFILE_C1B_OWNER_DRAIN:
        return owner.build_owner_command(
            exp, sequence, command_id or f"{sequence:032x}")
    return owner.build_owner_command(
        exp, sequence, command_id or f"{sequence:032x}",
        snapshot_sha256=digest or ("a" if sequence == 1 else "b") * 64,
        snapshot_revision=revision or (7 + sequence))


def ack_for(exp, parsed, *, phase=None, digest=None, revision=None,
            received=100, completed=200, accepted=True, failure=None):
    if digest is None:
        digest = (exp.initial_snapshot_sha256 if parsed.action == "drain"
                  else parsed.snapshot_sha256)
    if revision is None:
        revision = (exp.initial_revision if parsed.action == "drain"
                    else parsed.snapshot_revision)
    if phase is None:
        phase = ("removing" if parsed.action == "remove" else "draining")
    return {
        "schema_version": 1, "event": "owner_control_ack",
        "run_id": parsed.run_id, "worker_boot_id": parsed.worker_boot_id,
        "sequence": parsed.sequence, "command_id": parsed.command_id,
        "command_sha256": parsed.command_sha256, "action": parsed.action,
        "accepted": accepted, "failure_code": failure,
        "received_monotonic_ns": received, "completed_monotonic_ns": completed,
        "phase": phase, "applied_snapshot_sha256": digest,
        "applied_revision": revision,
    }


def make_archive(files, *, mode=0o600, uid=1000, gid=1000, names=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in (tuple(files) if names is None else names):
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mode, info.uid, info.gid = mode, uid, gid
            info.mtime = 1
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(files[name]))
    return stream.getvalue()


def material_fixture():
    exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
    files = {
        "install-snapshot.json": b"signed-install-policy",
        "remove-snapshot.json": b"signed-remove-policy",
        "install-intent.json": b"install-intent-envelope",
        "removal-intent.json": b"remove-intent-envelope",
    }
    wrapper = {
        "schema_version": 1, "event": "owner_materials_ready",
        "profile": exp.profile, "run_id": exp.run_id, "nonce": exp.nonce,
        "worker_boot_id": exp.worker_boot_id,
        "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in files.items()},
    }
    return exp, wrapper, files, make_archive(files)


class OwnerExpectationAndCommandTests(unittest.TestCase):
    def test_expectation_is_frozen_and_has_exact_eight_fields(self):
        exp = expected()
        self.assertEqual(tuple(field.name for field in fields(exp)), (
            "profile", "run_id", "nonce", "worker_boot_id", "manifest_fingerprint",
            "endpoint", "initial_snapshot_sha256", "initial_revision"))
        with self.assertRaises((AttributeError, TypeError)):
            exp.run_id = "9" * 32
        for changes in (
                {"run_id": True}, {"initial_revision": True},
                {"initial_revision": 0}, {"endpoint": "host:0"},
                {"profile": "baseline-v1"}):
            values = dict(profile=exp.profile, run_id=exp.run_id, nonce=exp.nonce,
                          worker_boot_id=exp.worker_boot_id,
                          manifest_fingerprint=exp.manifest_fingerprint,
                          endpoint=exp.endpoint,
                          initial_snapshot_sha256=exp.initial_snapshot_sha256,
                          initial_revision=exp.initial_revision)
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(owner.OwnerProtocolError):
                owner.OwnerExpectation(**values)

    def test_profiles_return_exact_seven_observations(self):
        self.assertEqual(owner.owner_profile_steps(owner.PROFILE_C1B_OWNER_DRAIN), (
            (1, "greedy-one-token"), (2, "forced-length-1"),
            (3, "forced-length-128"), (4, "forced-length-1024"),
            (5, "owner-drain-held"), (6, "owner-drain-controls"),
            (7, "owner-drain-paused")))
        self.assertEqual(owner.owner_profile_steps(owner.PROFILE_C1B_OWNER_REMOVE)[4:], (
            (5, "owner-remove-held"), (6, "owner-remove-revoked"),
            (7, "owner-remove-final")))
        with self.assertRaises(owner.OwnerProtocolError):
            owner.owner_profile_steps("c1b-owner-other-v1")

    def test_commands_and_requests_match_the_actual_inbox_parser(self):
        for profile in owner.OWNER_PROFILES:
            exp = expected(profile)
            for sequence in (1, 2):
                document = command(profile, sequence)
                request = owner.build_owner_action_request(exp, sequence, document)
                parsed = owner.validate_owner_action_request(request, exp)
                self.assertIsInstance(parsed, owner.OwnerCommand)
                self.assertEqual(parsed.sequence, sequence)
                self.assertEqual(parsed.command_sha256, request["command_sha256"])
                self.assertEqual(parsed.action,
                                 "drain" if profile == owner.PROFILE_C1B_OWNER_DRAIN
                                 else ("install_snapshot" if sequence == 1 else "remove"))

    def test_action_request_rejects_profile_identity_order_digest_and_schema_changes(self):
        exp = expected()
        request = owner.build_owner_action_request(
            exp, 1, command(owner.PROFILE_C1B_OWNER_DRAIN, 1))
        mutations = (
            lambda value: value.update(command_number=2),
            lambda value: value.update(command_sha256="f" * 64),
            lambda value: value.update(nonce="9" * 32),
            lambda value: value.update(unexpected=True),
            lambda value: value["command"].update(action="remove"),
            lambda value: value["command"].update(sequence=True),
            lambda value: value.update(event="owner_action_response"),
        )
        for mutate in mutations:
            broken = copy.deepcopy(request)
            mutate(broken)
            with self.subTest(broken=broken), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_action_request(broken, exp)

    def test_raw_action_request_rejects_duplicate_noncanonical_and_float_json(self):
        exp = expected()
        request = owner.build_owner_action_request(
            exp, 1, command(owner.PROFILE_C1B_OWNER_DRAIN, 1))
        canonical = owner._canonical_bytes(request)
        self.assertIsInstance(owner.validate_owner_action_request(canonical, exp),
                              owner.OwnerCommand)
        duplicate = canonical.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_action_request(duplicate, exp)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_action_request(canonical + b" ", exp)
        broken = copy.deepcopy(request)
        broken["command_number"] = 1.0
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_action_request(broken, exp)

    def test_ack_is_exactly_bound_to_claimed_command_and_policy(self):
        exp = expected()
        for sequence, phase in ((1, "draining"), (2, "paused")):
            request = owner.build_owner_action_request(
                exp, sequence, command(owner.PROFILE_C1B_OWNER_DRAIN, sequence))
            parsed = owner.validate_owner_action_request(request, exp)
            ack = ack_for(exp, parsed, phase=phase)
            self.assertIs(owner.validate_owner_command_ack(ack, parsed, exp), ack)
            for mutate in (
                    lambda value: value.update(accepted=1),
                    lambda value: value.update(failure_code="owner_unavailable"),
                    lambda value: value.update(command_sha256="f" * 64),
                    lambda value: value.update(completed_monotonic_ns=99),
                    lambda value: value.update(applied_snapshot_sha256="e" * 64),
                    lambda value: value.update(applied_revision=8),
                    lambda value: value.update(phase="ready"),
                    lambda value: value.update(unexpected=True),
            ):
                broken = copy.deepcopy(ack)
                mutate(broken)
                with self.subTest(broken=broken), self.assertRaises(owner.OwnerProtocolError):
                    owner.validate_owner_command_ack(broken, parsed, exp)

    def test_snapshot_ack_and_remove_phase_match_exact_command(self):
        exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
        for sequence in (1, 2):
            request = owner.build_owner_action_request(
                exp, sequence, command(exp.profile, sequence))
            parsed = owner.validate_owner_action_request(request, exp)
            ack = ack_for(exp, parsed, phase=("paused" if sequence == 1 else "removing"))
            self.assertIs(owner.validate_owner_command_ack(ack, parsed, exp), ack)
            broken = copy.deepcopy(ack)
            broken["applied_revision"] += 1
            with self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_command_ack(broken, parsed, exp)

    def test_signed_intent_is_command_bound_canonical_and_p256_only(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

        exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
        request = owner.build_owner_action_request(
            exp, 1, command(exp.profile, 1))
        parsed = owner.validate_owner_action_request(request, exp)
        key = ec.generate_private_key(ec.SECP256R1())
        encoded = owner.build_signed_owner_intent(parsed, key)
        envelope = json.loads(encoded)
        canonical_intent = json.dumps(envelope["intent"], sort_keys=True,
                                      separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(encoded, owner._canonical_bytes(envelope, maximum=owner.MAX_INTENT_BYTES))
        signature = base64.b64decode(envelope["signature"], validate=True)
        self.assertGreaterEqual(len(signature), 8)
        self.assertLessEqual(len(signature), 80)
        decode_dss_signature(signature)
        key.public_key().verify(signature,
                                b"steamboat-owner-removal-intent-v1\x00" + canonical_intent,
                                ec.ECDSA(hashes.SHA256()))
        self.assertEqual(envelope["intent"]["command_sha256"], parsed.command_sha256)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.build_signed_owner_intent(
                owner.validate_owner_action_request(
                    owner.build_owner_action_request(
                        expected(), 1, command(owner.PROFILE_C1B_OWNER_DRAIN, 1)), expected()),
                key)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.build_signed_owner_intent(parsed, ec.generate_private_key(ec.SECP384R1()))
        private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                        NoEncryption())
        self.assertEqual(json.loads(owner.build_signed_owner_intent(parsed, private_pem))[
            "intent"], envelope["intent"])


class OwnerMaterialArchiveTests(unittest.TestCase):
    def test_material_wrapper_and_fixed_ustar_bytes_validate(self):
        exp, wrapper, files, archive = material_fixture()
        self.assertIs(owner.validate_owner_materials_ready(wrapper, exp), wrapper)
        self.assertEqual(owner.validate_owner_material_archive(archive, wrapper, exp), files)
        wrapper_bytes = owner._canonical_bytes(wrapper)
        self.assertEqual(owner.validate_owner_material_archive(
            archive, wrapper_bytes, exp), files)
        for malformed in (
                wrapper_bytes + b" ",
                wrapper_bytes.replace(b'"event":"owner_materials_ready"',
                                      b'"event":"owner_materials_ready",'
                                      b'"event":"owner_materials_ready"', 1),
                b"{broken json}"):
            with self.subTest(malformed=malformed[:80]), self.assertRaises(
                    owner.OwnerProtocolError):
                owner.validate_owner_material_archive(archive, malformed, exp)

    def test_materials_wrapper_rejects_paths_extra_files_wrong_identity_and_bools(self):
        exp, wrapper, _files, _archive = material_fixture()
        mutations = (
            lambda value: value.update(path="/tmp/private"),
            lambda value: value.update(nonce="9" * 32),
            lambda value: value["files"].update({"secret.key": {"size": 1, "sha256": "a" * 64}}),
            lambda value: value["files"]["install-snapshot.json"].update(size=True),
            lambda value: value["files"]["remove-snapshot.json"].update(sha256="A" * 64),
            lambda value: value["files"].pop("removal-intent.json"),
        )
        for mutate in mutations:
            broken = copy.deepcopy(wrapper)
            mutate(broken)
            with self.subTest(broken=broken), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_materials_ready(broken, exp)

    def test_material_tar_rejects_digest_order_owner_mode_link_extra_and_truncation(self):
        exp, wrapper, files, archive = material_fixture()
        invalid = [archive[:517], make_archive(files, mode=0o644),
                   make_archive(files, uid=0), make_archive(files, gid=0)]
        reordered = dict(reversed(tuple(files.items())))
        invalid.append(make_archive(reordered))
        changed = dict(files)
        changed["install-snapshot.json"] = b"different-policy"
        invalid.append(make_archive(changed))
        linked = bytearray(archive)
        linked[156:157] = b"2"
        checksum = sum(linked[:148]) + (8 * ord(" ")) + sum(linked[156:512])
        linked[148:156] = f"{checksum:06o}\x00 ".encode("ascii")
        invalid.append(bytes(linked))
        invalid.append(make_archive(
            files, names=("install-snapshot.json", "install-snapshot.json",
                          "remove-snapshot.json", "install-intent.json",
                          "removal-intent.json")))
        unsafe = bytearray(archive)
        unsafe_name = b"../install-snapshot.json"
        unsafe[0:100] = unsafe_name + b"\x00" * (100 - len(unsafe_name))
        unsafe_checksum = sum(unsafe[:148]) + (8 * ord(" ")) + sum(unsafe[156:512])
        unsafe[148:156] = f"{unsafe_checksum:06o}\x00 ".encode("ascii")
        invalid.append(bytes(unsafe))
        invalid.append(archive + b"x" * 512)
        for encoded in invalid:
            with self.subTest(size=len(encoded)), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_material_archive(encoded, wrapper, exp)


class OwnerResponseSchemaTests(unittest.TestCase):
    def _config(self, exp):
        return {"account_id": "acct-owner", "device_id": "device-owner",
                "boot_id": exp.worker_boot_id, "assignment_id": "assign-owner",
                "model_id": "9" * 64, "model_revision": "rev-owner",
                "manifest_fingerprint": exp.manifest_fingerprint,
                "listen_ip": "10.1.2.3", "listen_port": 50061,
                "clock_uncertainty_seconds": 0.25}

    def _status(self, exp, config, parsed, *, event="heartbeat", lifecycle_phase=None,
                session_id=None, held=False, stopped=False):
        """Build worker status through the production serializer with tiny state seams."""
        import lab.secure_worker as worker

        def command_value(attribute, key):
            if parsed is None:
                return None
            return parsed[key] if type(parsed) is dict else getattr(parsed, attribute)

        sequence = 0 if parsed is None else command_value("sequence", "sequence")
        action = "" if parsed is None else command_value("action", "action")
        if lifecycle_phase is None:
            lifecycle_phase = "ready" if sequence == 0 else "draining"

        class Cache:
            def __init__(self, size):
                self.size = size

            def allocated_bytes(self):
                return self.size

            def lengths(self):
                return (1,) if self.size else ()

        class Bridge:
            def __init__(self, ready, owned_sessions, lifecycle):
                self.ready = ready
                self.owned_sessions = owned_sessions
                self.lifecycle = lifecycle
                self._closed = False

            def status(self):
                return {"ready": self.ready, "unavailable": False,
                    "requires_restart": False, "cleanup_confirmed": True,
                    "active_authorizations": 0, "owned_sessions": self.owned_sessions,
                    "pending_notices": 0, "fault": ""}

            def owner_lifecycle_status(self):
                return dict(self.lifecycle)

        class Budget:
            reserved_connections = 0 if stopped else 1
            reserved_pending = 0
            reserved_listener_pending_capacity = 0 if stopped else 1
            reserved_outbound_pending = 0

        class Handler:
            def __init__(self):
                self.sessions = {}
                self.tombstones = {}
                self._active_operation = None
                self._queue = []
                self.requires_restart = False
                self.stopping = False
                self.start, self.end = 6, 8
                self.max_tombstones = 4096
                self.queue_capacity = 8
                self.limits = {"max_sessions": 8, "max_positions": 1152,
                    "worker_cache_positions": 12288, "worker_cache_bytes": 16777216,
                    "max_message_bytes": 1048576}

        handler = Handler()
        if held:
            class Entry:
                in_flight = False
                committed_bytes = 128
                cache = Cache(128)
            handler.sessions[session_id] = Entry()
        if stopped:
            for _ in range(3):
                class Tombstone:
                    in_flight = False
                    committed_bytes = 0
                    cache = Cache(0)
                handler.tombstones[f"ses_{len(handler.tombstones):032x}"] = Tombstone()

        config_object = SimpleNamespace(
            worker_name="worker-3", account_id=config["account_id"],
            device_id=config["device_id"], boot_id=exp.worker_boot_id,
            assignment_id=config["assignment_id"], model_id=config["model_id"],
            model_revision=config["model_revision"],
            manifest_fingerprint=exp.manifest_fingerprint,
            endpoint=ENDPOINT, clock_uncertainty_seconds=0.25)
        lifecycle = {"phase": lifecycle_phase,
            "drain_started_monotonic": None if lifecycle_phase == "ready" else 10.0,
            "drain_deadline_monotonic": None if lifecycle_phase == "ready" else 40.0,
            "deadline_reached": lifecycle_phase == "paused"}
        owned = worker._OwnedRuntime(
            handler=handler,
            bridge=Bridge(lifecycle_phase == "ready" and not stopped,
                          1 if held else 0, lifecycle),
            bridge_started=True,
            budget=Budget(), server=SimpleNamespace(_stopped=stopped),
            torch_threads=2, owner_controls_enabled=True,
            owner_lifecycle_cache=lifecycle,
            owner_control_run_id=exp.run_id,
            owner_control_last_sequence=sequence,
            owner_control_last_command_sha256="" if parsed is None else command_value(
                "command_sha256", "command_sha256"),
            owner_control_last_action=action,
            owner_control_received_monotonic_ns=0 if parsed is None else (
                command_value("received_monotonic_ns", "received_monotonic_ns")
                if type(parsed) is dict else (100 if sequence == 1 else 300)),
            owner_control_applied_monotonic_ns=0 if parsed is None else (
                command_value("completed_monotonic_ns", "completed_monotonic_ns")
                if type(parsed) is dict else (200 if sequence == 1 else 400)),
            owner_control_applied_snapshot_sha256="" if parsed is None else (
                command_value("applied_snapshot_sha256", "applied_snapshot_sha256")
                if type(parsed) is dict else (exp.initial_snapshot_sha256
                    if action == "drain" else parsed.snapshot_sha256)),
            owner_control_applied_revision=0 if parsed is None else (
                command_value("applied_revision", "applied_revision")
                if type(parsed) is dict else (exp.initial_revision
                    if action == "drain" else parsed.snapshot_revision)),
            owner_control_removal_intent_verified=(False if parsed is None else action != "drain"),
            owner_control_revocation_notice_monotonic_ns=(150 if parsed is not None
                and action != "drain" and sequence == 1 else 0))
        shutdown = ({"server": "confirmed", "bridge": "confirmed",
                     "handler": "confirmed", "overall": "confirmed"}
                    if stopped else None)
        phase = "stopped" if event == "final" else (
            "draining" if event == "status" else lifecycle_phase)
        return worker._status_payload(config_object, owned, event=event, phase=phase,
                                      shutdown=shutdown)

    @staticmethod
    def _receipt(kind, digest, size):
        return {"schema_version": 1, "event": "owner_file_publication", "kind": kind,
                "sha256": digest, "size": size, "uid": 1000, "gid": 1000, "mode": 0o600,
                "file_fsync_confirmed": True, "directory_fsync_confirmed": True,
                "readback_confirmed": True}

    def _response(self, exp, sequence):
        doc = command(exp.profile, sequence)
        request = owner.build_owner_action_request(exp, sequence, doc)
        parsed = owner.validate_owner_action_request(request, exp)
        canonical_command = owner._canonical_bytes(owner._command_document(parsed))
        publication = {"install_intent": None, "removal_intent": None,
                       "policy": None,
                       "command": self._receipt(f"command{sequence}", parsed.command_sha256,
                                                len(canonical_command))}
        if exp.profile == owner.PROFILE_C1B_OWNER_REMOVE:
            publication["install_intent"] = self._receipt("install_intent", "a" * 64, 20)
            publication["removal_intent"] = self._receipt("removal_intent", "b" * 64, 21)
            publication["policy"] = self._receipt(f"policy{sequence}", parsed.snapshot_sha256, 30)
        ack = ack_for(exp, parsed,
                      received=100 if sequence == 1 else 300,
                      completed=200 if sequence == 1 else 400)
        if exp.profile == owner.PROFILE_C1B_OWNER_DRAIN:
            status = self._status(exp, self._config(exp), parsed,
                event="heartbeat", lifecycle_phase="draining",
                session_id="ses_" + "a" * 32, held=True)
        elif sequence == 1:
            status = self._status(exp, self._config(exp), parsed,
                event="heartbeat", lifecycle_phase="draining")
        else:
            status = self._status(exp, self._config(exp), parsed,
                event="status", lifecycle_phase="paused")
        response = {"schema_version": 1, "event": "owner_action_response",
                    "profile": exp.profile, "run_id": exp.run_id, "nonce": exp.nonce,
                    "worker_boot_id": exp.worker_boot_id, "command_number": sequence,
                    "command_sha256": parsed.command_sha256,
                    "publication": publication,
                    "worker_ack": ack,
                    "protected_status": {"measurement_label": "ssh_protected_owner_status_v1",
                        "ssh_host_key_sha256": "6" * 64, "remote_mark_ns": 10,
                        "heartbeat_mtime_ns": 11, "remote_status_uid": 1000,
                        "remote_status_mode": 0o600,
                        "remote_status": status}}
        return request, response

    def _result_fixture(self, profile, *, remove_terminal_event="final",
                        remove_terminal_lifecycle="paused", remove_revoked_held=False):
        exp = expected(profile)
        responses = [self._response(exp, sequence)[1] for sequence in (1, 2)]
        parsed = [owner.validate_owner_command_ack(row["worker_ack"],
                  owner._command_dict(command(profile, sequence), exp), exp)
                  for sequence, row in enumerate(responses, 1)]
        request_id, session_id, route_id = ("req_" + "a" * 32, "ses_" + "a" * 32,
                                             "route_" + "a" * 32)
        probe = {"request_id": request_id, "session_id": session_id, "route_id": route_id,
                 "route_epoch": 1, "attempt": 1,
                 "open_response": {"code": "OK", "session_id": session_id,
                                   "worker_boot_id": exp.worker_boot_id},
                 "step_response": {"sequence": 0, "start_position": 0, "token_count": 3,
                    "end_position": 3, "next_sequence": 1, "tensor_shape": [1, 3, 64],
                    "dtype": "float32_le", "byte_count": 768, "finite": True},
                 "bindings": []}
        for method, operation in (("OpenSession", "1"), ("Step", "2")):
            probe["bindings"].append({"method": method, "operation_id": "op_" + operation * 32,
                "request_id": request_id, "session_id": session_id, "route_id": route_id,
                "route_epoch": 1, "attempt": 1, "worker_boot_id": exp.worker_boot_id})
        def binding(method, operation, fresh=False):
            suffix = operation * 32
            return {"method": method, "operation_id": "op_" + suffix,
                "request_id": ("req_" + operation * 32 if fresh else request_id),
                "session_id": ("ses_" + operation * 32 if fresh else session_id),
                "route_id": ("route_" + operation * 32 if fresh else route_id),
                "route_epoch": 1, "attempt": 1, "worker_boot_id": exp.worker_boot_id}
        def denial(method, operation, fresh=False):
            return {"method": method, "binding": binding(method, operation, fresh),
                    "native_status": "UNAUTHENTICATED", "returned_response": False,
                    "dispatch_count": 1, "policy_sha256": exp.initial_snapshot_sha256}
        if profile == owner.PROFILE_C1B_OWNER_DRAIN:
            controls = {"continued_step": {"binding": binding("Step", "3"), "response": {
                "sequence": 1, "start_position": 3, "token_count": 1, "end_position": 4,
                "next_sequence": 2, "tensor_shape": [1, 1, 64], "dtype": "float32_le",
                "byte_count": 256, "finite": True}},
                "renew": {"binding": binding("RenewSession", "4"),
                          "response": {"code": "OK", "worker_boot_id": exp.worker_boot_id,
                                       "session_id": session_id}},
                "describe": {"code": "OK", "worker_boot_id": exp.worker_boot_id,
                    "ready": False, "active_sessions": 1, "reserved_positions": 12,
                    "allocated_cache_bytes": 128, "active_operations": 0,
                    "queued_operations": 0, "tombstones": 0, "cache_bytes_exact": True,
                    "requires_restart": False},
                "new_open_rejection": denial("OpenSession", "5", True)}
        else:
            controls = {"old_session_status_rejection": denial("SessionStatus", "3"),
                        "new_open_rejection": denial("OpenSession", "4", True)}
        observations = []
        for seq, case_id in owner.owner_profile_steps(profile)[4:]:
            if seq == 5:
                status = self._status(exp, self._config(exp), None,
                    event="heartbeat", lifecycle_phase="ready",
                    session_id=session_id, held=True)
            else:
                command_number = 2 if profile == owner.PROFILE_C1B_OWNER_DRAIN or seq == 7 else 1
                held = ((profile == owner.PROFILE_C1B_OWNER_DRAIN and seq == 6)
                        or (profile == owner.PROFILE_C1B_OWNER_REMOVE and seq == 6
                            and remove_revoked_held))
                phase = (remove_terminal_lifecycle
                         if seq == 7 and profile == owner.PROFILE_C1B_OWNER_REMOVE
                         else "paused" if seq == 7 else "draining")
                if seq == 7 and profile == owner.PROFILE_C1B_OWNER_REMOVE:
                    event = remove_terminal_event
                else:
                    event = "heartbeat"
                status = self._status(exp, self._config(exp), parsed[command_number - 1],
                    event=event, lifecycle_phase=phase,
                    session_id=session_id, held=held,
                    stopped=(seq == 7 and profile == owner.PROFILE_C1B_OWNER_REMOVE
                             and event == "final"))
            observation_mark = (responses[1]["protected_status"]["remote_mark_ns"]
                                if seq == 7 and profile == owner.PROFILE_C1B_OWNER_REMOVE
                                else 500 if seq == 7 else 100 + seq)
            observations.append({"schema_version": 1, "event": "observation_ack",
                "run_id": exp.run_id, "nonce": exp.nonce, "sequence": seq,
                "case_id": case_id, "request_id": request_id, "session_id": session_id,
                "boot_id": exp.worker_boot_id, "manifest_fingerprint": exp.manifest_fingerprint,
                "endpoint": exp.endpoint, "ssh_host_key_sha256": "6" * 64,
                "remote_status_uid": 1000, "remote_status_mode": 0o600,
                "supervisor_monotonic_ns": 1000 + seq, "remote_mark_ns": observation_mark,
                "heartbeat_mtime_ns": observation_mark + 1,
                "measurement_label": "ssh_protected_owner_status_v1", "remote_status": status})
        labels = ["initial", "new_open"] if profile == owner.PROFILE_C1B_OWNER_DRAIN else [
            "initial", "old_status", "new_open"]
        closes = [{"label": label, "attempted": True, "confirmed": True, "close_calls": 1,
            "reserved_connections_before": 3, "reserved_connections_after": 0,
            "client_closed": True, "reserved_pending_after": 0} for label in labels]
        actions = {"profile": profile, "status": "passed", "scope": "remote_host_owner_control",
            "target_device_id": self._config(exp)["device_id"], "worker_boot_id": exp.worker_boot_id,
            "initial_snapshot_sha256": exp.initial_snapshot_sha256, "initial_revision": exp.initial_revision,
            "initial_local_serials": ["a1", "b2"],
            "old_local_shutdown": {"confirmed": True, "failure_types": []},
            "direct_probe": probe, "commands": responses, "controls": controls,
            "observations": observations, "probe_cleanup": {"confirmed": True,
                "failure_types": [], "client_closes": closes, "contexts_released": 2,
                "authorizations_closed": 2, "transport_reserved_connections": 0,
                "transport_reserved_pending": 0, "transport_reserved_outbound_pending": 0,
                "transport_reserved_listener_pending_capacity": 0}}
        reqs = [f"req_{index:032x}" for index in range(1, 5)]
        sessions = [f"ses_{index:032x}" for index in range(1, 5)]
        result = {"schema_version": 1, "event": "result", "run_id": exp.run_id,
            "baseline": {"status": "passed", "completed_requests": 4, "captured_vectors": 27},
            "request_ids": reqs, "session_ids": sessions,
            "numerical_errors": {"captured_vectors": 27, "values": [0.0] * 27,
                                  "atol": 1e-3, "rtol": 0.0, "max_absolute_error": 0.0},
            "cases": [{"case_id": case_id, "request_id": reqs[i], "session_id": sessions[i]}
                      for i, case_id in enumerate(("greedy-one-token", "forced-length-1",
                          "forced-length-128", "forced-length-1024"))],
            "local_shutdown": {"confirmed": True}, "remote_shutdown": {"confirmed": True},
            "pending_scope": [], "identities": {}, "owner_actions": actions}
        return exp, result

    def test_action_response_drain_and_remove_round_trip(self):
        for profile in owner.OWNER_PROFILES:
            exp = expected(profile)
            for sequence in (1, 2):
                request, response = self._response(exp, sequence)
                with self.subTest(profile=profile, sequence=sequence):
                    self.assertIs(owner.validate_owner_action_response(
                        response, request, exp, expected_ssh_host_key_sha256="6" * 64,
                        expected_worker_config=self._config(exp)), response)

    def test_remove_command_two_accepts_actual_final_status_alternative(self):
        exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
        request, response = self._response(exp, 2)
        ack = owner.validate_owner_command_ack(
            response["worker_ack"], owner._command_dict(command(exp.profile, 2), exp), exp)
        response["protected_status"]["remote_status"] = self._status(
            exp, self._config(exp), ack, event="final", lifecycle_phase="paused", stopped=True)
        self.assertIs(owner.validate_owner_action_response(
            response, request, exp, expected_ssh_host_key_sha256="6" * 64,
            expected_worker_config=self._config(exp)), response)

    def test_action_response_rejects_provenance_command_ack_and_status_aliases(self):
        exp = expected()
        request, response = self._response(exp, 1)
        for mutate in (
                lambda item: item.update(worker_boot_id="9" * 32),
                lambda item: item.update(command_sha256="f" * 64),
                lambda item: item["protected_status"].update(ssh_host_key_sha256="7" * 64),
                lambda item: item["protected_status"].update(heartbeat_mtime_ns=True),
                lambda item: item["worker_ack"].update(accepted=1),
                lambda item: item["publication"]["command"].update(size=True),
                lambda item: item["protected_status"]["remote_status"]["owner_control"].update(
                    last_sequence=True),
        ):
            broken = copy.deepcopy(response)
            try:
                mutate(broken)
            except TypeError:
                pass
            with self.subTest(mutate=mutate), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_action_response(
                    broken, request, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))

    def test_owner_json_float_is_confined_to_status_clock_fields(self):
        exp = expected()
        request, response = self._response(exp, 1)
        encoded = owner._canonical_bytes_owner(response, maximum=owner.MAX_RECORD_BYTES)
        self.assertEqual(owner._owner_record(encoded, maximum=owner.MAX_RECORD_BYTES,
                                             label="test response"), response)
        broken = copy.deepcopy(response)
        broken["protected_status"]["remote_status"]["handler"]["active_sessions"] = 0.0
        encoded = owner._canonical_bytes_owner(broken, maximum=owner.MAX_RECORD_BYTES)
        with self.assertRaises(owner.OwnerProtocolError):
            owner._owner_record(encoded, maximum=owner.MAX_RECORD_BYTES, label="test response")

    def test_remove_response_rejects_policy_intent_and_causal_mark_edits(self):
        exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
        request, response = self._response(exp, 1)
        for mutate in (
                lambda item: item["publication"]["policy"].update(sha256="f" * 64),
                lambda item: item["publication"]["install_intent"].update(size=True),
                lambda item: item["protected_status"].update(heartbeat_mtime_ns=10),
                lambda item: item["protected_status"]["remote_status"]["owner_control"].update(
                    revocation_notice_monotonic_ns=9_999_999_999),
                lambda item: item.update(nonce="9" * 32),
        ):
            broken = copy.deepcopy(response)
            mutate(broken)
            with self.subTest(mutate=mutate), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_action_response(
                    broken, request, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))

    def test_result_rejects_legacy_profiles_and_unbounded_or_duplicate_json(self):
        exp = expected()
        # A result from an old profile must never gain acceptance merely by carrying
        # an owner_actions extension. Full positives use producer-created records.
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                {"schema_version": 1, "event": "result", "run_id": exp.run_id,
                 "owner_actions": {}}, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

    def test_owner_result_drain_and_remove_schema_fixtures(self):
        for profile in owner.OWNER_PROFILES:
            exp, result = self._result_fixture(profile)
            encoded = owner._canonical_bytes_owner(result["owner_actions"], maximum=65_536)
            with self.subTest(profile=profile):
                self.assertIs(owner.validate_owner_result(
                    result["owner_actions"], exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp)), result["owner_actions"])
                self.assertEqual(owner.validate_owner_result(
                    encoded, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp)), result["owner_actions"])
        exp, status_result = self._result_fixture(
            owner.PROFILE_C1B_OWNER_REMOVE, remove_terminal_event="status")
        self.assertIs(owner.validate_owner_result(
            status_result["owner_actions"], exp, expected_ssh_host_key_sha256="6" * 64,
            expected_worker_config=self._config(exp)), status_result["owner_actions"])
        live_final = status_result["owner_actions"]["observations"][2]["remote_status"]
        self.assertEqual(live_final["phase"], "draining")
        self.assertEqual(live_final["owner_lifecycle"]["phase"], "paused")
        self.assertIs(live_final["bridge"]["ready"], False)
        self.assertIs(live_final["bridge"]["unavailable"], False)
        self.assertEqual(live_final["transport"]["server_state"], "running")
        self.assertEqual(live_final["transport"]["listener_slots"], 1)
        self.assertEqual(live_final["transport"]["reserved_connections"], 1)
        self.assertEqual(live_final["transport"]["reserved_listener_pending_capacity"], 1)
        exp_draining, draining_result = self._result_fixture(
            owner.PROFILE_C1B_OWNER_REMOVE, remove_terminal_event="status",
            remove_terminal_lifecycle="draining")
        self.assertIs(owner.validate_owner_result(
            draining_result["owner_actions"], exp_draining,
            expected_ssh_host_key_sha256="6" * 64,
            expected_worker_config=self._config(exp_draining)),
            draining_result["owner_actions"])
        for event, mutation in (
                ("final", lambda status: status["shutdown"].update(server="not_started")),
                ("final", lambda status: status["transport"].update(server_state="running")),
                ("status", lambda status: status["transport"].update(reserved_connections=0)),
                ("status", lambda status: status.update(phase="paused")),
        ):
            _, invalid = self._result_fixture(
                owner.PROFILE_C1B_OWNER_REMOVE, remove_terminal_event=event)
            mutation(invalid["owner_actions"]["observations"][2]["remote_status"])
            with self.subTest(event=event, mutation=mutation), self.assertRaises(
                    owner.OwnerProtocolError):
                owner.validate_owner_result(
                    invalid["owner_actions"], exp,
                    expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))
        duplicate = b'{"schema_version":1,"event":"result","run_id":"' + \
            exp.run_id.encode("ascii") + b'","run_id":"' + exp.run_id.encode("ascii") + b'"}'
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(duplicate, exp,
                expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

    def test_drain_command_status_must_keep_the_original_probe_session(self):
        exp, result = self._result_fixture(owner.PROFILE_C1B_OWNER_DRAIN)
        self.assertIs(owner.validate_owner_result(
            result["owner_actions"], exp, expected_ssh_host_key_sha256="6" * 64,
            expected_worker_config=self._config(exp)), result["owner_actions"])
        for mutation in (
                lambda status: status["handler"].update(active_session_ids=[],
                    active_sessions=0, committed_cache_bytes=0, allocated_cache_bytes=0,
                    **{}),
                lambda status: status["handler"].update(active_session_ids=["ses_" + "f" * 32]),
        ):
            broken = copy.deepcopy(result["owner_actions"])
            mutation(broken["commands"][0]["protected_status"]["remote_status"])
            with self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_result(
                    broken, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))

    def test_action_status_requires_cutoff_and_exact_raw_status_bound(self):
        exp = expected()
        request, response = self._response(exp, 1)
        for mutation in (
                lambda status: status["bridge"].update(ready=True),
                lambda status: status.update(event="status"),
        ):
            broken = copy.deepcopy(response)
            mutation(broken["protected_status"]["remote_status"])
            with self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_action_response(
                    broken, request, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))
        oversized = copy.deepcopy(response)
        oversized["protected_status"]["remote_status"]["worker_name"] = "w" * 5000
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_action_response(
                oversized, request, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

    def test_command_ack_order_and_terminal_observation_mark_are_correlated(self):
        exp, result = self._result_fixture(owner.PROFILE_C1B_OWNER_REMOVE)
        broken = copy.deepcopy(result["owner_actions"])
        first = broken["commands"][0]
        second = broken["commands"][1]
        second["worker_ack"]["received_monotonic_ns"] = 199
        second["worker_ack"]["completed_monotonic_ns"] = 250
        second["protected_status"]["remote_status"]["owner_control"].update(
            received_monotonic_ns=199, applied_monotonic_ns=250)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                broken, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))
        broken = copy.deepcopy(result["owner_actions"])
        broken["observations"][2]["remote_mark_ns"] += 1
        broken["observations"][2]["heartbeat_mtime_ns"] += 1
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                broken, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))
        broken = copy.deepcopy(result["owner_actions"])
        broken["observations"][1]["session_id"] = "ses_" + "f" * 32
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                broken, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))
        broken = copy.deepcopy(result["owner_actions"])
        broken["observations"][1]["request_id"] = "req_" + "f" * 32
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                broken, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

    def test_final_drain_uses_fresh_heartbeat_not_command_two_frame(self):
        exp, result = self._result_fixture(owner.PROFILE_C1B_OWNER_DRAIN)
        actions = result["owner_actions"]
        command_mark = actions["commands"][1]["protected_status"]["remote_mark_ns"]
        final = actions["observations"][2]
        self.assertGreater(final["remote_mark_ns"], command_mark)
        self.assertEqual(final["remote_status"]["event"], "heartbeat")
        self.assertEqual(final["remote_status"]["phase"], "paused")
        self.assertEqual(final["remote_status"]["owner_lifecycle"]["deadline_reached"], True)
        self.assertIs(owner.validate_owner_result(
            actions, exp, expected_ssh_host_key_sha256="6" * 64,
            expected_worker_config=self._config(exp)), actions)
        broken = copy.deepcopy(actions)
        broken["observations"][2]["remote_mark_ns"] = command_mark
        broken["observations"][2]["heartbeat_mtime_ns"] = command_mark + 1
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                broken, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

    def test_paused_owner_cannot_retain_resources_and_remove_revocation_cleans_probe(self):
        exp = expected(owner.PROFILE_C1B_OWNER_DRAIN)
        request, response = self._response(exp, 2)
        parsed = owner.validate_owner_command_ack(
            response["worker_ack"], owner._command_dict(command(exp.profile, 2), exp), exp)
        response["protected_status"]["remote_status"] = self._status(
            exp, self._config(exp), parsed, event="heartbeat", lifecycle_phase="paused",
            session_id="ses_" + "a" * 32, held=True)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_action_response(
                response, request, exp, expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(exp))

        remove_exp, remove_result = self._result_fixture(
            owner.PROFILE_C1B_OWNER_REMOVE, remove_revoked_held=True)
        seq6 = remove_result["owner_actions"]["observations"][1]["remote_status"]
        self.assertEqual(seq6["event"], "heartbeat")
        self.assertEqual(seq6["owner_lifecycle"]["phase"], "draining")
        self.assertEqual(seq6["handler"]["active_sessions"], 1)
        with self.assertRaises(owner.OwnerProtocolError):
            owner.validate_owner_result(
                remove_result["owner_actions"], remove_exp,
                expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=self._config(remove_exp))

    def test_owner_serial_and_step_dimensions_reject_aliases(self):
        exp, result = self._result_fixture(owner.PROFILE_C1B_OWNER_DRAIN)
        for serial in ("0", "01", "a" * 41, "a" * 64):
            broken = copy.deepcopy(result["owner_actions"])
            broken["initial_local_serials"] = [serial]
            with self.subTest(serial=serial), self.assertRaises(owner.OwnerProtocolError):
                owner.validate_owner_result(
                    broken, exp, expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=self._config(exp))
        for sequence, shape, size in ((0, [True, 3, 64], 768),
                                      (1, [1, False, 64], 256)):
            with self.subTest(sequence=sequence), self.assertRaises(owner.OwnerProtocolError):
                owner._validate_step({"sequence": sequence, "start_position": 0,
                    "token_count": 3 if sequence == 0 else 1,
                    "end_position": 3 if sequence == 0 else 4,
                    "next_sequence": 1 if sequence == 0 else 2,
                    "tensor_shape": shape, "dtype": "float32_le", "byte_count": size,
                    "finite": True}, sequence=sequence, start=0,
                    count=3 if sequence == 0 else 1,
                    end=3 if sequence == 0 else 4,
                    next_sequence=1 if sequence == 0 else 2,
                    shape=[1, 3, 64] if sequence == 0 else [1, 1, 64], size=size)


@unittest.skipUnless(_POSIX_SAFE_READ, "worker intent verifier requires POSIX protected files")
class OwnerIntentWorkerInteropTests(unittest.TestCase):
    def test_signed_intent_is_accepted_by_actual_worker_verifier_and_rejects_mutation(self):
        from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat)
        import lab.secure_worker as worker

        exp = expected(owner.PROFILE_C1B_OWNER_REMOVE)
        request = owner.build_owner_action_request(
            exp, 1, command(exp.profile, 1))
        parsed = owner.validate_owner_action_request(request, exp)
        key = ec.generate_private_key(ec.SECP256R1())
        verifier_pem = key.public_key().public_bytes(Encoding.PEM,
                                                    PublicFormat.SubjectPublicKeyInfo)
        raw = owner.build_signed_owner_intent(parsed, key)
        with tempfile.TemporaryDirectory(prefix="owner-intent-test-") as directory:
            base = Path(directory)
            role_root, intent_root = base / "role", base / "intent"
            role_root.mkdir(mode=0o700)
            intent_root.mkdir(mode=0o700)
            os.chmod(role_root, 0o700)
            os.chmod(intent_root, 0o700)
            path = intent_root / "install-intent.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            config = SimpleNamespace(protected_root=str(role_root))
            verified = worker._verify_owner_removal_intent(
                config, parsed, str(intent_root), verification_key_pem=verifier_pem,
                filename="install-intent.json")
            self.assertEqual(verified["command_sha256"], parsed.command_sha256)
            remove_request = owner.build_owner_action_request(
                exp, 2, command(exp.profile, 2))
            remove_claim = owner.validate_owner_action_request(remove_request, exp)
            removal_path = intent_root / "removal-intent.json"
            removal_path.write_bytes(owner.build_signed_owner_intent(remove_claim, key))
            os.chmod(removal_path, 0o600)
            verified_remove = worker._verify_owner_removal_intent(
                config, remove_claim, str(intent_root),
                verification_key_pem=verifier_pem, filename="removal-intent.json")
            self.assertEqual(verified_remove["command_sha256"], remove_claim.command_sha256)
            wrong_key = ec.generate_private_key(ec.SECP256R1())
            wrong_pem = wrong_key.public_key().public_bytes(Encoding.PEM,
                                                            PublicFormat.SubjectPublicKeyInfo)
            with self.assertRaises(worker.WorkerConfigError):
                worker._verify_owner_removal_intent(
                    config, parsed, str(intent_root), verification_key_pem=wrong_pem,
                    filename="install-intent.json")
            envelope = json.loads(raw)
            signature = bytearray(base64.b64decode(envelope["signature"], validate=True))
            signature[-1] ^= 1
            envelope["signature"] = base64.b64encode(signature).decode("ascii")
            path.write_bytes(owner._canonical_bytes(envelope,
                                                    maximum=owner.MAX_INTENT_BYTES))
            os.chmod(path, 0o600)
            with self.assertRaises(worker.WorkerConfigError):
                worker._verify_owner_removal_intent(
                    config, parsed, str(intent_root), verification_key_pem=verifier_pem,
                    filename="install-intent.json")
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            other_request = owner.build_owner_action_request(
                exp, 2, command(exp.profile, 2, command_id="9" * 32))
            other_claim = owner.validate_owner_action_request(other_request, exp)
            with self.assertRaises(worker.WorkerConfigError):
                worker._verify_owner_removal_intent(
                    config, other_claim, str(intent_root),
                    verification_key_pem=verifier_pem,
                    filename="install-intent.json")
            envelope = json.loads(raw)
            envelope["intent"]["command_sha256"] = "f" * 64
            path.write_bytes(owner._canonical_bytes(envelope,
                                                    maximum=owner.MAX_INTENT_BYTES))
            os.chmod(path, 0o600)
            with self.assertRaises(worker.WorkerConfigError):
                worker._verify_owner_removal_intent(
                    config, parsed, str(intent_root), verification_key_pem=verifier_pem,
                    filename="install-intent.json")

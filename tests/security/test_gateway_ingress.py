from __future__ import annotations

import ssl
import threading
import tempfile
import unittest
import copy
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from steamboat_security.certificates import (certificate_sha256,
    generate_private_key_pem, public_key_sha256, serial_hex)
from steamboat_security.channel_certificates import (issue_channel_certificate,
    make_channel_csr)
from steamboat_security.channel_tls import (MAX_CHUNK_BYTES,
    MAX_HANDSHAKE_BYTES, OwnedWorkerTLS, OwnedWorkerTLSError,
    _valid_endpoint_host)
from steamboat_security.errors import ClockError
from steamboat_security.errors import ClockError
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.gateway_ingress import (GatewayIngressError,
    GatewayWorkerIngress)
from steamboat_security.sessions import SessionBindings
from tests.security import test_gateway_delegation as delegation_tests


class GatewayIngressTests(unittest.TestCase):
    def setUp(self):
        self._prior_delegation_now = delegation_tests.NOW
        delegation_tests.NOW = int(datetime.now(timezone.utc).timestamp()) - 30
        now = delegation_tests.NOW
        self._temp_paths = []
        self.fixture = delegation_tests.GatewayDelegationTests()
        self.fixture.setUp()
        self.worker_channel_key = generate_private_key_pem()
        worker_identity = {
            "account_id": self.fixture.payload["workers"][0]["account_id"],
            "device_id": self.fixture.payload["workers"][0]["device_id"],
            "host_serial": self.fixture.payload["workers"][0]["host_serial"],
            "credential_epoch": self.fixture.payload["workers"][0]["host_credential_epoch"],
        }
        csr = make_channel_csr(self.worker_channel_key, kind="worker_stream",
                               identity=worker_identity)
        self.worker_channel = issue_channel_certificate(
            self.fixture.gateway_ca, self.fixture.gateway_ca_key, csr,
            kind="worker_stream", identity=worker_identity,
            now=datetime.fromtimestamp(now, timezone.utc),
            lifetime_seconds=800)
        worker_cert = x509.load_pem_x509_certificate(self.worker_channel)
        payload = dict(self.fixture.payload)
        payload["revision"] = 2
        route = dict(payload["routes"][0])
        route["methods"] = sorted(("Describe", "OpenSession", "RenewSession", "Step",
                                   "CloseSession", "CancelSession", "SessionStatus"))
        payload["routes"] = [route]
        worker = dict(payload["workers"][0])
        worker.update(channel_serial=serial_hex(worker_cert.serial_number),
                      channel_certificate_sha256=certificate_sha256(worker_cert),
                      channel_public_key_sha256=public_key_sha256(worker_cert.public_key()))
        payload["workers"] = [worker]
        self.fixture.view = self.fixture.policy_store.install(
            sign_channel_policy(payload, delegation_tests.private_pem(self.fixture.operator_key)))
        self.gateway_cert_file = None
        self.worker_cert_file = None
        self.worker_key_file = None
        self.ca_file = None
        self.tls_owner = self._make_tls_client()
        self.sessions = SessionBindings(clock=self.fixture.clock)
        self.ingress = GatewayWorkerIngress.from_tls(
            self.tls_owner, verifier=self.fixture.verifier, sessions=self.sessions,
            gateway_id="gw-east")

    def tearDown(self):
        delegation_tests.NOW = self._prior_delegation_now
        self.fixture.tearDown() if hasattr(self.fixture, "tearDown") else None
        for path in self._temp_paths:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass

    def _write(self, data):
        file = tempfile.NamedTemporaryFile(delete=False)
        file.write(data)
        file.close()
        self._temp_paths.append(file.name)
        return file.name

    def _make_tls_client(self, hostname="gateway.example.net",
                         require_client_certificate=True):
        f = self.fixture
        self.gateway_cert_file = self._write(f.gateway_pem)
        self.worker_cert_file = self._write(self.worker_channel)
        self.worker_key_file = self._write(self.worker_channel_key)
        self.ca_file = self._write(f.gateway_ca)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.verify_mode = (ssl.CERT_REQUIRED if require_client_certificate
                                      else ssl.CERT_NONE)
        server_context.load_cert_chain(self.gateway_cert_file,
                                       self._write(f.gateway_key))
        if require_client_certificate:
            server_context.load_verify_locations(cafile=self.ca_file)
        ci, co, si, so = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
        server = server_context.wrap_bio(si, so, server_side=True)
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.worker_channel,
            worker_private_key_pem=self.worker_channel_key,
            gateway_ca_pem=self.fixture.gateway_ca,
            endpoint_host=hostname, endpoint_port=443, clock=self.fixture.clock)
        server_done = False
        for _ in range(30):
            outgoing = owner.take_encrypted()
            if outgoing:
                si.write(outgoing)
            try:
                server.do_handshake()
                server_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            response = so.read() if so.pending else b""
            if response:
                owner.feed_encrypted(response)
            else:
                owner.do_handshake()
            if owner.handshake_complete:
                for _ in range(3):
                    if server_done:
                        break
                    final_client = owner.take_encrypted()
                    if final_client:
                        si.write(final_client)
                    try:
                        server.do_handshake()
                        server_done = True
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                owner._test_server = server
                owner._test_server_handshake_done = server_done
                owner._test_server_incoming = si
                owner._test_server_outgoing = so
                return owner
        raise AssertionError("MemoryBIO TLS handshake did not complete")

    def test_real_mutual_tls_connection_binds_policy_and_unique_generation(self):
        self.assertIs(type(self.tls_owner), OwnedWorkerTLS)
        self.assertTrue(self.tls_owner.handshake_complete)
        sent, received = self.tls_owner.byte_counts
        self.assertGreater(sent, 0)
        self.assertGreater(received, 0)
        self.assertEqual(self.ingress.policy_revision, 2)
        self.assertEqual(len(self.ingress.stream_generation), 32)
        self.assertEqual(self.ingress.ingress_identity[0], "gateway-v1")
        self.assertFalse(self.ingress.poll_unavailable())
        self.assertTrue(_valid_endpoint_host("2001:db8::1"))
        self.assertFalse(_valid_endpoint_host("https://gateway.example.net"))
        self.assertFalse(_valid_endpoint_host("*.example.net"))

    def test_client_handshake_does_not_prove_server_verified_worker_certificate(self):
        owner = self._make_tls_client(require_client_certificate=False)
        self.assertTrue(owner.handshake_complete)
        self.assertTrue(owner._test_server_handshake_done)
        self.assertIsNone(owner._test_server.getpeercert(binary_form=True))
        self.assertTrue(owner.configured_local_certificate_pem)
        owner.close()
        self.assertTrue(_valid_endpoint_host("2001:db8::1"))
        self.assertFalse(_valid_endpoint_host("https://gateway.example.net"))
        self.assertFalse(_valid_endpoint_host("*.example.net"))

    def test_wrong_endpoint_tls_handshake_is_rejected(self):
        with self.assertRaises(OwnedWorkerTLSError):
            self._make_tls_client("other.example.net")
            # A TLS client that does not validate the fixed gateway endpoint
            # cannot reach the ingress constructor.
            raise AssertionError("wrong endpoint unexpectedly passed TLS")

    def test_owned_tls_requires_matching_client_leaf_and_private_key(self):
        with self.assertRaises(OwnedWorkerTLSError):
            OwnedWorkerTLS.connect(
                worker_certificate_pem=self.worker_channel,
                worker_private_key_pem=generate_private_key_pem(),
                gateway_ca_pem=self.fixture.gateway_ca,
                endpoint_host="gateway.example.net", endpoint_port=443,
                clock=self.fixture.clock)
        with self.assertRaises(OwnedWorkerTLSError):
            OwnedWorkerTLS.connect(
                worker_certificate_pem=b"", worker_private_key_pem=self.worker_channel_key,
                gateway_ca_pem=self.fixture.gateway_ca,
                endpoint_host="gateway.example.net", endpoint_port=443,
                clock=self.fixture.clock)

    def test_wrong_worker_certificate_cannot_become_ingress(self):
        wrong_key = generate_private_key_pem()
        identity = dict(self.fixture.payload["workers"][0])
        wrong_identity = {
            "account_id": identity["account_id"], "device_id": "dev_" + "f" * 32,
            "host_serial": identity["host_serial"],
            "credential_epoch": identity["host_credential_epoch"],
        }
        csr = make_channel_csr(wrong_key, kind="worker_stream", identity=wrong_identity)
        wrong_cert = issue_channel_certificate(
            self.fixture.gateway_ca, self.fixture.gateway_ca_key, csr,
            kind="worker_stream", identity=wrong_identity,
            now=datetime.fromtimestamp(delegation_tests.NOW, timezone.utc),
            lifetime_seconds=800)
        file = self._write(wrong_cert)
        key_file = self._write(wrong_key)
        owner = self._make_tls_client_with_credential(wrong_cert, wrong_key, file, key_file)
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(
                owner, verifier=self.fixture.verifier,
                sessions=self.sessions, gateway_id="gw-east")
        self.assertFalse(owner.handshake_complete)
        owner.close()

    def _make_tls_client_with_credential(self, certificate, key, cert_file, key_file):
        f = self.fixture
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.verify_mode = ssl.CERT_REQUIRED
        server_context.load_cert_chain(self.gateway_cert_file,
                                       self._write(f.gateway_key))
        server_context.load_verify_locations(cafile=self.ca_file)
        si, so = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = server_context.wrap_bio(si, so, server_side=True)
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=certificate, worker_private_key_pem=key,
            gateway_ca_pem=f.gateway_ca, endpoint_host="gateway.example.net",
            endpoint_port=443, clock=f.clock)
        for _ in range(30):
            encrypted = owner.take_encrypted()
            if encrypted:
                si.write(encrypted)
            try:
                server.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            response = so.read() if so.pending else b""
            if response:
                owner.feed_encrypted(response)
            else:
                owner.do_handshake()
            if owner.handshake_complete:
                return owner
        return owner

    def test_incomplete_and_closed_owned_tls_cannot_create_ingress(self):
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.worker_channel,
            worker_private_key_pem=self.worker_channel_key,
            gateway_ca_pem=self.fixture.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=self.fixture.clock)
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(owner, verifier=self.fixture.verifier,
                                          sessions=self.sessions, gateway_id="gw-east")
        owner.close()
        with self.assertRaises(OwnedWorkerTLSError):
            owner.feed_encrypted(b"x")

    def test_owned_tls_chunk_and_handshake_deadline_bounds_are_sticky(self):
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.worker_channel,
            worker_private_key_pem=self.worker_channel_key,
            gateway_ca_pem=self.fixture.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=self.fixture.clock)
        with self.assertRaises(OwnedWorkerTLSError):
            owner.feed_encrypted(b"x" * (MAX_CHUNK_BYTES + 1))
        with self.assertRaises(OwnedWorkerTLSError):
            owner.do_handshake()

    def test_completed_tls_stream_remains_live_after_handshake_deadline(self):
        owner = self.tls_owner
        server = owner._test_server
        incoming = owner._test_server_incoming
        outgoing = owner._test_server_outgoing
        self.fixture.mono += 10.001
        self.fixture.wall += 10.001
        owner.write_plaintext(b"request")
        encrypted = owner.take_encrypted()
        incoming.write(encrypted)
        self.assertEqual(server.read(32), b"request")
        server.write(b"response")
        response = outgoing.read()
        self.assertTrue(response)
        owner.feed_encrypted(response)
        self.assertEqual(owner.read_plaintext(), b"response")
        self.assertGreaterEqual(sum(owner.byte_counts), len(encrypted) + len(response))

    def test_clock_provider_failure_sticks_after_clock_revalidation(self):
        owner = self.tls_owner
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(OwnedWorkerTLSError):
            owner.feed_encrypted(b"x")
        self.assertFalse(owner.is_live)
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(OwnedWorkerTLSError):
            owner.do_handshake()
        self.assertTrue(self.ingress.poll_unavailable())
        self.assertTrue(self.ingress._state.closed)

    def test_owner_clock_fault_cannot_resume_after_clock_revalidation(self):
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(OwnedWorkerTLSError):
            self.tls_owner.feed_encrypted(b"x")
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        self.assertFalse(self.tls_owner.is_live)
        with self.assertRaises(OwnedWorkerTLSError):
            self.tls_owner.do_handshake()
        self.assertTrue(self.ingress.poll_unavailable())
        self.assertLessEqual(MAX_HANDSHAKE_BYTES, 128 * 1024)
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.worker_channel,
            worker_private_key_pem=self.worker_channel_key,
            gateway_ca_pem=self.fixture.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=self.fixture.clock)
        self.fixture.mono += 10
        with self.assertRaises(OwnedWorkerTLSError):
            owner.do_handshake()
        with self.assertRaises(OwnedWorkerTLSError):
            owner.do_handshake()

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX file modes only")
    def test_tls_credential_files_are_removed_before_connection_is_returned(self):
        import os
        import tempfile
        from unittest.mock import patch
        from steamboat_security import channel_tls
        before = set(os.listdir(tempfile.gettempdir()))
        observed = []
        original_remove = channel_tls.shutil.rmtree
        def observe_remove(path, *args, **kwargs):
            if os.path.basename(path).startswith("steamboat-channel-"):
                modes = {os.path.basename(item): os.stat(os.path.join(path, item)).st_mode & 0o777
                         for item in os.listdir(path)}
                observed.append((os.stat(path).st_mode & 0o777, modes))
            return original_remove(path, *args, **kwargs)
        with patch.object(channel_tls.shutil, "rmtree", side_effect=observe_remove):
            owner = OwnedWorkerTLS.connect(
                worker_certificate_pem=self.worker_channel,
                worker_private_key_pem=self.worker_channel_key,
                gateway_ca_pem=self.fixture.gateway_ca,
                endpoint_host="gateway.example.net", endpoint_port=443,
                clock=self.fixture.clock)
        after = set(os.listdir(tempfile.gettempdir()))
        self.assertEqual({name for name in after - before
                          if name.startswith("steamboat-channel-")}, set())
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], 0o700)
        self.assertEqual(set(observed[0][1].values()), {0o600})
        owner.close()

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX descriptor semantics")
    def test_fsync_failure_does_not_double_close_reused_descriptor(self):
        import os
        from unittest.mock import patch
        from steamboat_security import channel_tls
        original_fdopen = os.fdopen
        sentinel_fd = []

        class ClosingProxy:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.stream.close()
                sentinel_fd.append(os.open(os.devnull, os.O_RDONLY))
            def write(self, value):
                return self.stream.write(value)
            def flush(self):
                return self.stream.flush()
            def fileno(self):
                return self.stream.fileno()

        def wrapped_fdopen(fd, *args, **kwargs):
            return ClosingProxy(original_fdopen(fd, *args, **kwargs))

        with patch.object(channel_tls.os, "fdopen", side_effect=wrapped_fdopen), \
                patch.object(channel_tls.os, "fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaises(OSError):
                OwnedWorkerTLS.connect(
                    worker_certificate_pem=self.worker_channel,
                    worker_private_key_pem=self.worker_channel_key,
                    gateway_ca_pem=self.fixture.gateway_ca,
                    endpoint_host="gateway.example.net", endpoint_port=443,
                    clock=self.fixture.clock)
        self.assertEqual(len(sentinel_fd), 1)
        os.fstat(sentinel_fd[0])
        os.close(sentinel_fd[0])

    def test_cleanup_failure_returns_unusable_owner_with_uncertain_path(self):
        import os
        from unittest.mock import patch
        from steamboat_security import channel_tls
        original_remove = channel_tls.shutil.rmtree
        failures = []

        def fail_once(path, *args, **kwargs):
            failures.append(path)
            raise OSError("injected cleanup failure")

        with patch.object(channel_tls.shutil, "rmtree", side_effect=fail_once):
            owner = OwnedWorkerTLS.connect(
                worker_certificate_pem=self.worker_channel,
                worker_private_key_pem=self.worker_channel_key,
                gateway_ca_pem=self.fixture.gateway_ca,
                endpoint_host="gateway.example.net", endpoint_port=443,
                clock=self.fixture.clock)
            self.assertTrue(owner.cleanup_uncertain)
            self.assertEqual(owner.cleanup_status, "uncertain")
            path = owner._private_directory
            self.assertTrue(path and os.path.isdir(path))
            self.assertFalse(owner.handshake_complete)
            owner.close()
            self.assertEqual(len(failures), 1)
            self.assertEqual(owner._private_directory, path)
        original_remove(path, ignore_errors=False)

    def test_global_sequence_replay_permanently_closes_generation(self):
        with self.assertRaises(GatewayIngressError):
            self.ingress.heartbeat(self.ingress.stream_generation, 2)
        self.assertTrue(self.ingress.poll_unavailable())
        with self.assertRaises(GatewayIngressError):
            self.ingress.heartbeat(self.ingress.stream_generation, 1)

    def test_late_heartbeat_cannot_revive_timed_out_stream_before_poll(self):
        self.fixture.mono += 60.001
        self.fixture.wall += 60.001
        with self.assertRaises(GatewayIngressError):
            self.ingress.heartbeat(self.ingress.stream_generation, 1)
        self.assertTrue(self.ingress._state.closed)
        self.assertTrue(self.ingress.poll_unavailable())

    def test_operation_after_heartbeat_timeout_mints_no_guard(self):
        self.fixture.mono += 60.001
        self.fixture.wall += 60.001
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        with self.assertRaises(GatewayIngressError):
            self.ingress.verify_operation(
                envelope, self.fixture.metadata, self.fixture.request, 1)
        self.assertTrue(self.ingress._state.closed)
        self.assertEqual(len(self.ingress._guards), 0)

    def test_operation_after_policy_refresh_mints_no_guard(self):
        replacement = dict(self.fixture.payload)
        replacement["revision"] = 3
        self.fixture.policy_store.install(sign_channel_policy(
            replacement, delegation_tests.private_pem(self.fixture.operator_key)))
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        with self.assertRaises(GatewayIngressError):
            self.ingress.verify_operation(
                envelope, self.fixture.metadata, self.fixture.request, 1)
        self.assertTrue(self.ingress._state.closed)
        self.assertEqual(len(self.ingress._guards), 0)

    def test_liveness_fault_retires_before_clock_revalidation_can_resume(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.ingress._policy_and_worker

        def blocked_failure():
            entered.set()
            self.assertTrue(release.wait(2))
            raise GatewayIngressError("policy changed during liveness check")

        self.ingress._policy_and_worker = blocked_failure
        result = []
        thread = threading.Thread(
            target=lambda: result.append(self.ingress.poll_unavailable()))
        thread.start()
        self.assertTrue(entered.wait(2))
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(ClockError):
            self.fixture.clock.sample()
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        release.set()
        thread.join(2)
        self.ingress._policy_and_worker = original
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [True])
        self.assertTrue(self.ingress._state.closed)
        self.assertTrue(self.ingress.poll_unavailable())

    def test_admission_transaction_serializes_close_until_claim_work_finishes(self):
        entered = threading.Event()
        release = threading.Event()
        closed = threading.Event()
        errors = []

        def admit():
            try:
                with self.ingress.admission_transaction():
                    entered.set()
                    self.assertTrue(release.wait(2))
            except Exception as error:
                errors.append(error)

        admission = threading.Thread(target=admit)
        admission.start()
        self.assertTrue(entered.wait(2))
        closer = threading.Thread(target=lambda: (self.ingress.close(), closed.set()))
        closer.start()
        self.assertFalse(closed.wait(0.05))
        release.set()
        admission.join(2)
        closer.join(2)
        self.assertFalse(admission.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(closed.is_set())
        self.assertTrue(self.ingress._state.closed)

    def test_admission_transaction_performs_final_policy_check(self):
        with self.assertRaises(GatewayIngressError):
            with self.ingress.admission_transaction():
                replacement = dict(self.fixture.payload)
                replacement["revision"] = 3
                self.fixture.policy_store.install(sign_channel_policy(
                    replacement, delegation_tests.private_pem(self.fixture.operator_key)))
        self.assertTrue(self.ingress._state.closed)

    def test_admission_exception_preserves_c1_error_but_latches_clock_fault(self):
        with self.assertRaises(ValueError):
            with self.ingress.admission_transaction():
                raise ValueError("ordinary local C1 denial")
        self.assertFalse(self.ingress._state.closed)

        def broken_clock():
            raise RuntimeError("clock source unavailable")
        with self.assertRaises(ClockError):
            with self.ingress.admission_transaction():
                self.fixture.clock._uncertainty = broken_clock
                self.fixture.clock.sample()
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        self.assertTrue(self.ingress._state.closed)
        self.assertTrue(self.ingress.poll_unavailable())

    def test_operation_guard_is_owned_and_tracks_ingress_liveness(self):
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        guard = self.ingress.verify_operation(
            envelope, self.fixture.metadata, self.fixture.request, 1)
        self.assertTrue(guard.assert_live())
        self.assertGreater(guard.deadline_monotonic, self.fixture.mono)
        self.ingress.close()
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()

    def test_clock_fault_permanently_retires_existing_operation_guard(self):
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        guard = self.ingress.verify_operation(
            envelope, self.fixture.metadata, self.fixture.request, 1)
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()

    def test_wrong_gateway_id_and_fabricated_ssl_object_are_rejected(self):
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(
            self.tls_owner, verifier=self.fixture.verifier,
            sessions=self.sessions, gateway_id="gw-other")
        with self.assertRaises(TypeError):
            GatewayWorkerIngress.from_tls(
                object(), verifier=self.fixture.verifier, sessions=self.sessions,
                gateway_id="gw-east")
        raw_ssl = self.tls_owner._OwnedWorkerTLS__ssl
        with self.assertRaises(TypeError):
            GatewayWorkerIngress.from_tls(
                raw_ssl, verifier=self.fixture.verifier, sessions=self.sessions,
                gateway_id="gw-east")
        with self.assertRaises(TypeError):
            copy.copy(self.tls_owner)
        fabricated = object.__new__(OwnedWorkerTLS)
        with self.assertRaises(TypeError):
            GatewayWorkerIngress.from_tls(
                fabricated, verifier=self.fixture.verifier, sessions=self.sessions,
                gateway_id="gw-east")

    def test_one_tls_object_cannot_mint_multiple_stream_generations(self):
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(
                self.tls_owner, verifier=self.fixture.verifier,
                sessions=self.sessions, gateway_id="gw-east")

    def test_old_generation_close_does_not_close_replacement_connection(self):
        replacement_tls = self._make_tls_client()
        replacement = GatewayWorkerIngress.from_tls(
            replacement_tls, verifier=self.fixture.verifier,
            sessions=self.sessions, gateway_id="gw-east")
        self.assertNotEqual(self.ingress.stream_generation,
                            replacement.stream_generation)
        self.ingress.close()
        self.assertFalse(replacement.poll_unavailable())

    def test_policy_refresh_retires_existing_tls_generation(self):
        replacement = dict(self.fixture.payload)
        replacement["revision"] = 3
        self.fixture.policy_store.install(sign_channel_policy(
            replacement, delegation_tests.private_pem(self.fixture.operator_key)))
        self.assertTrue(self.ingress.poll_unavailable())
        self.assertTrue(self.ingress._state.closed)


if __name__ == "__main__":
    unittest.main()

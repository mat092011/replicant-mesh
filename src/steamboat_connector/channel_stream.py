"""Metered bootstrap and bounded framing over one owned TLS socket stream.

This component stops at decoded C2 bundles. It does not dispatch methods,
authorize application calls, negotiate model generations, or claim readiness.
"""

from __future__ import annotations

import struct
import threading
import weakref

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import (
    CoordinatorHelloClient, CoordinatorHelloServer,
    WorkerHelloClient, WorkerHelloServer,
)
from steamboat_connector.channel_socket import (
    MAX_PENDING_PLAINTEXT, ChannelBackpressure,
    ChannelSocket, ChannelSocketError,
)
from steamboat_connector.channel_wire import PendingMessageLanes
from steamboat_connector.channel_writer import (
    ChannelFragmentWriter, writer_reservation_overhead_bytes,
)


SOCKET_SCRATCH_RESERVATION_BYTES = 8 * MAX_PENDING_PLAINTEXT
HELLO_RESERVATION_BYTES = 2 * (wire.FRAGMENT_HEADER_BYTES + 4096)
DECODED_METADATA_RESERVATION_BYTES = 16 * 512
TLS_OWNER_MIN_RESERVATION_BYTES = 4 * 64 * 1024
_CLIENT_TYPES = (WorkerHelloClient, CoordinatorHelloClient)
_SERVER_TYPES = (WorkerHelloServer, CoordinatorHelloServer)
_HELLO_TYPES = _CLIENT_TYPES + _SERVER_TYPES
_STREAM_LOCK = threading.Lock()
_REGISTERED_WORKER_STREAMS = weakref.WeakSet()
_CLAIMED_DRIVERS = weakref.WeakSet()
_CLAIMED_TLS_OWNERS = weakref.WeakSet()


class ChannelStreamError(RuntimeError):
    """The authenticated framed stream was retired or is not ready."""


class ChannelStream:
    """Compose one exact socket driver and one exact C2 HELLO owner.

    The constructor is post-TLS: the caller first drives the owned TLS
    handshake through ``ChannelSocket`` and passes the same driver and HELLO
    owner here. A client queues its one HELLO frame at construction; a server
    derives and queues its ACK only from actual driver plaintext.
    """

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("framed stream state and owners are immutable to callers")
        object.__setattr__(self, name, value)

    def _set(self, name, value):
        object.__setattr__(self, name, value)

    def __init__(self, driver, hello_owner, *, writer_reservation_bytes,
                 decoded_byte_capacity, tls_owner_reservation_bytes):
        if type(driver) is not ChannelSocket or type(hello_owner) not in _HELLO_TYPES:
            raise TypeError("framed stream needs exact ChannelSocket and HELLO owners")
        if type(writer_reservation_bytes) is not int or type(decoded_byte_capacity) is not int:
            raise TypeError("writer and decoded-message reservations must be explicit integers")
        if (type(tls_owner_reservation_bytes) is not int
                or tls_owner_reservation_bytes < TLS_OWNER_MIN_RESERVATION_BYTES):
            raise ValueError("TLS owner memory reservation is below its bounded BIO minimum")
        self._driver = driver
        self._hello = hello_owner
        self._server = type(hello_owner) in _SERVER_TYPES
        self._tls = driver._tls
        self._check_owner_binding()
        if (hello_owner._state != "hello"
                or (type(hello_owner) in _CLIENT_TYPES and hello_owner._hello_sent)
                or (type(hello_owner) in _SERVER_TYPES and hello_owner._ack_sent)):
            raise ChannelStreamError("HELLO owner was already used outside this socket stream")
        if not driver.tls_handshake_complete:
            raise ChannelStreamError("TLS handshake must complete through the socket driver first")
        if (driver.pending_plaintext_bytes or driver.pending_ciphertext_bytes
                or self._tls.pending_encrypted_bytes):
            raise ChannelStreamError("drain TLS/socket output before starting HELLO bootstrap")
        if (decoded_byte_capacity < 1
                or writer_reservation_bytes < writer_reservation_overhead_bytes() + 1):
            raise ValueError("decoded queue or writer reservation is too small")
        self._decoded_byte_capacity = decoded_byte_capacity
        self._writer_reservation_bytes = writer_reservation_bytes
        self._tls_owner_reservation_bytes = tls_owner_reservation_bytes
        decoder_bytes = (hello_owner.decoder_reservation_bytes
                         or hello_owner.reassembly_capacity * 2
                         + wire.MAX_WIRE_FRAME_BYTES + wire.MAX_FEED_BYTES
                         + min(hello_owner.reassembly_capacity, wire.MAX_BUNDLE_BYTES)
                         + 64 * 1024)
        self._reservation_bound_bytes = (
            decoder_bytes + writer_reservation_bytes + decoded_byte_capacity
            + DECODED_METADATA_RESERVATION_BYTES + SOCKET_SCRATCH_RESERVATION_BYTES
            + HELLO_RESERVATION_BYTES
            + tls_owner_reservation_bytes)
        self._lock = threading.RLock()
        self._writer = None
        self._decoder = None
        self._incoming = None
        self._outgoing_frame = None
        self._bootstrap_outstanding = False
        self._bootstrap_complete = False
        self._deferred_plaintext = None
        self._incoming_cleanup_mode = False
        self._closed = False
        self._failure = None
        self._sealed = True
        with _STREAM_LOCK:
            if driver in _CLAIMED_DRIVERS or self._tls in _CLAIMED_TLS_OWNERS:
                raise ChannelStreamError("socket driver or TLS owner already belongs to a stream")
            _CLAIMED_DRIVERS.add(driver)
            _CLAIMED_TLS_OWNERS.add(self._tls)
        # Disable the HELLO classes' direct MemoryBIO test helpers as soon as
        # this stream claims their TLS owner. The stream itself uses only the
        # byte-feed/validation methods and ChannelSocket for transport.
        if type(hello_owner) in _CLIENT_TYPES:
            hello_owner._hello_sent = True
        else:
            hello_owner._ack_sent = True
        if type(hello_owner) in _CLIENT_TYPES:
            # The complete immutable HELLO frame is offered exactly once and
            # only as plaintext to the same metered TLS socket driver.
            try:
                driver.offer_plaintext(hello_owner.hello_frame, kind="data")
            except Exception as error:
                self._retire("could not queue the one HELLO frame", error)

    @property
    def failure(self):
        return self._failure

    @property
    def closed(self):
        return self._closed

    @property
    def cleanup_status(self):
        """Local close request state; not an independent reclamation proof."""
        return "close_requested" if self._closed else "active"

    @property
    def socket_byte_counts(self):
        return self._driver.socket_byte_counts

    @property
    def io_outcome_uncertain(self):
        return self._driver.io_outcome_uncertain

    @property
    def metering_uncertain(self):
        return self._driver.metering_uncertain

    @property
    def transport_bootstrap_complete(self):
        """True after HELLO/ACK is committed and any server ACK is fully sent."""
        if self._bootstrap_complete and not self._closed:
            with self._lock:
                self._require_ready()
        return self._bootstrap_complete and not self._closed

    @property
    def registration(self):
        if not self._server or not self.transport_bootstrap_complete:
            return None
        with self._lock:
            self._require_ready()
            try:
                registration = self._hello.registration
                if registration is not None:
                    registration.assert_live()
                return registration
            except Exception as error:
                self._retire("worker registration is no longer live", error)

    @property
    def writer(self):
        return self._writer

    @property
    def decoder(self):
        return self._decoder

    @property
    def reservation_bound_bytes(self):
        """Decoder + writer + decoded queue + socket/TLS/scratch reservation."""
        return self._reservation_bound_bytes

    @property
    def decoded_pending_bytes(self):
        if self._incoming is None:
            return 0
        return self._incoming.pending_bytes

    @property
    def pending_outgoing_frame_bytes(self):
        return len(self._outgoing_frame) if self._outgoing_frame is not None else 0

    def _check_owner_binding(self):
        if type(self._hello) is WorkerHelloClient:
            owned = self._hello.tls_owner
        elif type(self._hello) is WorkerHelloServer:
            owned = self._hello.owner
        elif type(self._hello) is CoordinatorHelloClient:
            owned = self._hello.egress
        else:
            owned = self._hello.owner
        if owned is not self._tls:
            raise TypeError("HELLO and socket driver do not share the exact TLS owner")

    def pump(self):
        """Drive bounded socket/TLS work, then consume one bounded plaintext chunk."""
        with self._lock:
            self._require_live()
            try:
                self._check_owner_binding()
                self._assert_owner_live()
                socket_status = self._driver.pump()
                self._acknowledge_drained_output()
                if self._deferred_plaintext is not None and self._bootstrap_complete:
                    data = self._deferred_plaintext
                    self._set("_deferred_plaintext", None)
                    self._feed_application(data)
                plaintext = self._driver.take_plaintext()
                if plaintext is not None:
                    self._consume_plaintext(plaintext)
                self._acknowledge_drained_output()
                self._queue_next_writer_frame()
                return {"transport_bootstrap_complete": self.transport_bootstrap_complete,
                        "pending_outgoing_frame_bytes": self.pending_outgoing_frame_bytes,
                        "decoded_pending_bytes": self.decoded_pending_bytes,
                        "socket_byte_counts": self._driver.socket_byte_counts,
                        "backpressure": socket_status["backpressure"]}
            except ChannelBackpressure:
                return {"transport_bootstrap_complete": self.transport_bootstrap_complete,
                        "pending_outgoing_frame_bytes": self.pending_outgoing_frame_bytes,
                        "decoded_pending_bytes": self.decoded_pending_bytes,
                        "socket_byte_counts": self._driver.socket_byte_counts,
                        "backpressure": "bounded transport backpressure"}
            except ChannelStreamError:
                raise
            except ChannelSocketError as error:
                self._retire("socket transport retired", error)
            except BaseException as error:
                self._retire("framed stream processing failed", error)

    tick = pump

    def _consume_plaintext(self, plaintext):
        if type(plaintext) is not bytes or not plaintext or len(plaintext) > MAX_PENDING_PLAINTEXT:
            self._retire("socket driver returned malformed plaintext")
        if not self._bootstrap_complete:
            if self._server:
                try:
                    ack = self._hello.feed_hello(plaintext)
                except Exception as error:
                    self._retire("HELLO validation failed", error)
                if ack is not None:
                    if self._bootstrap_outstanding:
                        self._retire("HELLO server produced more than one ACK")
                    self._driver.offer_plaintext(ack, kind="data")
                    self._set("_bootstrap_outstanding", True)
                elif self._driver.pending_plaintext_bytes:
                    self._retire("unexpected server plaintext before HELLO commit")
                return
            try:
                decoder = self._hello.feed_ack(plaintext)
            except Exception as error:
                self._retire("HELLO ACK validation failed", error)
            if decoder is not None:
                self._commit_bootstrap(decoder)
            return
        if self._server and self._bootstrap_outstanding:
            if self._deferred_plaintext is not None:
                self._retire("more plaintext arrived before the HELLO ACK drained")
            self._set("_deferred_plaintext", plaintext)
            return
        self._feed_application(plaintext)

    def _acknowledge_drained_output(self):
        if self._bootstrap_outstanding and self._transport_drained():
            self._set("_bootstrap_outstanding", False)
            self._commit_bootstrap(self._hello.decoder)
        if self._outgoing_frame is not None and self._transport_drained():
            frame = self._outgoing_frame
            try:
                self._writer.frame_sent(frame)
            except Exception as error:
                self._retire("writer could not acknowledge drained frame", error)
            self._set("_outgoing_frame", None)

    def _transport_drained(self):
        return (self._driver.pending_plaintext_bytes == 0
                and self._driver.pending_ciphertext_bytes == 0
                and self._tls.pending_encrypted_bytes == 0)

    def _commit_bootstrap(self, decoder):
        if self._bootstrap_complete:
            return
        if decoder is None or decoder is not self._hello.decoder:
            self._retire("HELLO owner did not commit its decoder")
        try:
            self._set("_writer", ChannelFragmentWriter(
                decoder.expected_generation,
                communication_reservation_bytes=self._writer_reservation_bytes,
                initial_sequence=self._hello.initial_sequence))
            self._set("_incoming", PendingMessageLanes(
                byte_capacity=self._decoded_byte_capacity))
            self._set("_decoder", decoder)
            self._set("_bootstrap_complete", True)
            if self._server and type(self._hello) is WorkerHelloServer:
                with _STREAM_LOCK:
                    _REGISTERED_WORKER_STREAMS.add(self)
        except Exception as error:
            self._retire("could not initialize bounded framed lanes", error)

    def _feed_application(self, plaintext):
        if not self.transport_bootstrap_complete or self._incoming is None:
            self._retire("application plaintext arrived before HELLO/ACK completion")
        iterator = None
        try:
            iterator = self._decoder.feed(plaintext)
            for message in iterator:
                if message.kind == wire.HELLO:
                    self._retire("unexpected HELLO frame after bootstrap commit")
                if (self._incoming_cleanup_mode
                        and message.kind in wire.DATA_KINDS):
                    self._retire("data message arrived after cleanup-only mode")
                if message.kind in (wire.DATA, wire.RESPONSE, wire.CONTROL,
                                    wire.CONTROL_RESPONSE):
                    wire.decode_bundle(message.payload, fragment_kind=message.kind)
                if not self._incoming.enqueue(message):
                    self._retire("decoded message queue capacity exhausted")
        except Exception as error:
            self._retire("framed plaintext failed validation or admission", error)
        finally:
            if iterator is not None:
                try:
                    iterator.close()
                except Exception as error:
                    self._retire("decoder iterator cleanup failed", error)

    def enqueue(self, *, kind, message_id, payload):
        """Queue one prevalidated bundle; control frames preempt between fragments."""
        with self._lock:
            self._require_ready()
            if kind == wire.HELLO:
                raise ValueError("HELLO is owned and emitted only by the bootstrap")
            try:
                accepted = self._writer.enqueue(kind=kind, message_id=message_id,
                                                payload=payload)
            except Exception as error:
                self._retire("writer admission failed", error)
            if not accepted:
                raise ChannelBackpressure("bounded frame writer is full or rejected the bundle")
            return True

    def pop_message(self):
        """Return the next decoded bundle, with cleanup/control priority."""
        with self._lock:
            self._require_ready()
            return self._incoming.pop_next()

    def enter_incoming_cleanup_mode(self):
        """Irreversibly meter incoming socket traffic as cleanup-only."""
        with self._lock:
            self._require_ready()
            if self._incoming_cleanup_mode:
                return
            try:
                self._decoder.enter_control_only()
                self._driver.set_incoming_cleanup_mode(True)
            except Exception as error:
                self._retire("could not enter incoming cleanup-only mode", error)
            self._set("_incoming_cleanup_mode", True)

    def _queue_next_writer_frame(self):
        if (not self._bootstrap_complete or self._outgoing_frame is not None
                or self._writer is None or not self._transport_drained()):
            return
        try:
            frame = self._writer.next_frame()
        except Exception as error:
            self._retire("writer could not commit its next frame", error)
        if frame is None:
            return
        kind = wire.HELLO
        try:
            kind = struct.unpack_from(wire.FRAGMENT_FORMAT, frame)[1]
        except Exception as error:
            self._retire("writer returned a malformed fragment", error)
        budget_kind = "cleanup" if kind in wire.CONTROL_KINDS else "data"
        self._set("_outgoing_frame", frame)
        try:
            self._driver.offer_plaintext(frame, kind=budget_kind)
        except Exception as error:
            self._retire("socket driver rejected a committed writer frame", error)

    def _require_live(self):
        if self._closed:
            raise ChannelStreamError(self._failure or "framed stream is closed")

    def _require_ready(self):
        self._require_live()
        self._check_owner_binding()
        self._assert_owner_live()
        if not self._bootstrap_complete:
            raise ChannelStreamError("HELLO/ACK transport bootstrap is incomplete")

    def _assert_owner_live(self):
        if (type(self._hello) is WorkerHelloClient
                and self._hello.ingress.poll_unavailable()):
            self._retire("worker ingress policy or heartbeat expired")
        try:
            self._tls.assert_transport_live()
        except Exception as error:
            self._retire("TLS owner policy, clock, or credential is no longer live", error)

    def _retire(self, reason, cause=None):
        if self._closed:
            raise ChannelStreamError(self._failure or reason) from cause
        self._set("_closed", True)
        self._set("_failure", reason)
        if self._writer is not None:
            try:
                self._writer.retire()
            except Exception:
                pass
        try:
            self._driver.close()
        except Exception:
            pass
        if self._incoming is not None:
            self._set("_incoming", None)
        self._set("_decoder", None)
        raise ChannelStreamError(reason) from cause

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._set("_closed", True)
            self._set("_failure", "framed stream closed")
            if self._writer is not None:
                self._writer.retire()
            self._set("_incoming", None)
            self._set("_decoder", None)
            self._driver.close()


def is_registered_worker_channel_stream(value):
    """Recognize only a live server stream committed through the actual driver."""
    if type(value) is not ChannelStream:
        return False
    with _STREAM_LOCK:
        if value not in _REGISTERED_WORKER_STREAMS:
            return False
    try:
        if (not value.transport_bootstrap_complete or value.closed
                or type(value._hello) is not WorkerHelloServer
                or value._writer is None
                or type(value._writer) is not ChannelFragmentWriter):
            return False
        registration = value.registration
        if registration is None:
            return False
        registration.assert_live()
    except Exception:
        return False
    return True

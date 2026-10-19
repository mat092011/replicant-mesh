"""Bounded child-side validation for supervisor-inherited artifact pins.

The fixed role adapter must call ``validate_child_pin`` after its startup gate
opens and before loading model artifacts. The adapter supplies its trusted
core Clock and CatalogVerifier; this helper does not select a trust root.
"""

import base64
import binascii
import os
from dataclasses import dataclass

from steamboat_security.clock import Clock
from steamboat_connector.catalog import (CatalogVerifier, MAX_ASSIGNMENT_BYTES,
                                         MAX_CATALOG_BYTES)
from steamboat_connector.validation import json_bytes


MAX_HANDOFF_BYTES = 65_536
_SINGLE_FIELDS = {
    "version", "kind", "role", "root", "uid", "record_path", "record",
    "global_fd", "role_fd", "clock_domain", "captured_mono", "catalog_deadline",
    "assignment_deadline", "signed_catalog", "signed_assignment", "public_key",
}
_GROUP_FIELDS = {
    "version", "kind", "role", "root", "uid", "record_path", "record",
    "global_fd", "role_fd", "clock_domain", "captured_mono", "catalog_deadline",
    "signed_catalog", "public_key", "assignments",
}
_ASSIGNMENT_FIELDS = {
    "version", "component", "worker_boot_id", "assignment_deadline",
    "signed_assignment",
}


class RuntimePinHandoffError(ValueError):
    """The child could not establish inherited artifact ownership."""


@dataclass
class ChildArtifactPinSet:
    """One owner for all validated components and their assignment guards."""

    owners: tuple
    guards: tuple
    _state: str = "open"

    def close(self):
        if self._state == "closed":
            return
        if self._state != "open":
            raise RuntimePinHandoffError("child artifact pin cleanup is faulted")
        self._state = "closing"
        errors = []
        for owner in reversed(self.owners):
            try:
                close = getattr(owner, "close", None)
                if callable(close):
                    close()
                else:
                    close_partial = getattr(owner, "close_after_failed_acquire", None)
                    if not callable(close_partial):
                        raise RuntimePinHandoffError("pin owner has no close operation")
                    close_partial()
            except Exception as error:
                errors.append(error)
        self._state = "faulted" if errors else "closed"
        if errors:
            raise RuntimePinHandoffError("child artifact pin cleanup is uncertain") from errors[0]


def _decode(value, label, maximum):
    if type(value) is not str or len(value) > ((maximum + 2) // 3) * 4:
        raise RuntimePinHandoffError(f"{label} is malformed or oversized")
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise RuntimePinHandoffError(f"{label} is malformed") from error
    if len(result) > maximum:
        raise RuntimePinHandoffError(f"{label} is oversized")
    return result


def _closed_metadata(metadata, fields):
    if (type(metadata) is not dict or set(metadata) != fields
            or type(metadata.get("version")) is not int
            or metadata["version"] != 1):
        raise RuntimePinHandoffError("pin metadata fields or version are invalid")
    try:
        json_bytes(metadata, maximum_bytes=MAX_HANDOFF_BYTES)
    except (TypeError, ValueError) as error:
        raise RuntimePinHandoffError("pin metadata exceeds its closed size bound") from error


def _owner_for_partial_pair(global_fd, role_fd=None):
    from steamboat_connector.artifact_pin import PartialArtifactPinOwner
    owner = PartialArtifactPinOwner(global_fd, None)
    if role_fd is not None:
        owner.role_fd = role_fd
        owner._close_outcomes["role_fd"] = "open"
    return owner


def _attach_owner(error, owners, extra=None):
    previous = getattr(error, "pin_owner", None)
    retained = list(owners)
    if isinstance(previous, ChildArtifactPinSet):
        retained.extend(previous.owners)
    elif previous is not None:
        retained.append(previous)
    if extra is not None and all(extra is not item for item in retained):
        retained.append(extra)
    if retained:
        error.pin_owner = ChildArtifactPinSet(tuple(retained), ())


def validate_child_pin(metadata, *, clock, verifier):
    """Validate supervisor metadata using the fixed adapter's trusted objects.

    A successful aggregate call transfers the original descriptor pair to its
    first validated owner and makes one tracked ``dup`` pair per other
    assignment. Failed closes remain attached to the raised error as sticky
    owners; callers must retain that exception until process teardown.
    """
    if (type(clock) is not Clock or type(verifier) is not CatalogVerifier
            or verifier.clock is not clock):
        raise RuntimePinHandoffError("pin validation needs its exact core Clock and verifier")
    if type(metadata) is not dict:
        raise RuntimePinHandoffError("inherited pin metadata is malformed")
    kind = metadata.get("kind")
    fields = _SINGLE_FIELDS if kind == "single" else _GROUP_FIELDS if kind == "group" else None
    if fields is None:
        raise RuntimePinHandoffError("pin kind is unsupported")
    _closed_metadata(metadata, fields)
    role = metadata["role"]
    if (type(role) is not str or (kind == "single" and role != "coordinator")
            or (kind == "group" and role != "host")
            or type(metadata["record"]) is not dict
            or type(metadata["global_fd"]) is not int
            or type(metadata["role_fd"]) is not int
            or metadata["global_fd"] < 0 or metadata["role_fd"] < 0
            or metadata["global_fd"] == metadata["role_fd"]):
        raise RuntimePinHandoffError("inherited pin identity or descriptors are malformed")

    if kind == "single":
        signed_assignment = _decode(metadata["signed_assignment"], "signed assignment",
                                    MAX_ASSIGNMENT_BYTES)
        assignments = None
    else:
        assignments = metadata["assignments"]
        if type(assignments) is not list or not 1 <= len(assignments) <= 3:
            raise RuntimePinHandoffError("aggregate assignment count exceeds its bound")
        components = []
        decoded_assignments = []
        for item in assignments:
            if (type(item) is not dict or set(item) != _ASSIGNMENT_FIELDS
                    or type(item.get("version")) is not int or item["version"] != 1
                    or type(item.get("component")) is not str
                    or type(item.get("worker_boot_id")) is not str
                    or type(item.get("assignment_deadline")) not in (int, float)
                    or isinstance(item.get("assignment_deadline"), bool)):
                raise RuntimePinHandoffError("aggregate assignment metadata is malformed")
            components.append(item["component"])
            decoded_assignments.append(_decode(item["signed_assignment"],
                                               "signed assignment", MAX_ASSIGNMENT_BYTES))
        if len(set(components)) != len(components):
            raise RuntimePinHandoffError("aggregate components are duplicated")
        assignments = tuple(zip(assignments, decoded_assignments))

    public_key = _decode(metadata["public_key"], "catalog trust key", 65)
    if len(public_key) != 65 or public_key != verifier.public_key:
        raise RuntimePinHandoffError("inherited pin trust key differs from adapter trust")
    signed_catalog = _decode(metadata["signed_catalog"], "signed catalog", MAX_CATALOG_BYTES)

    from steamboat_connector.artifact_pin import validate_inherited_pin
    from steamboat_connector.aggregate_artifact_pin import validate_inherited_group_pin

    owners, guards = [], []
    if kind == "single":
        try:
            owner, guard = validate_inherited_pin(
                metadata["global_fd"], metadata["role_fd"], root=metadata["root"],
                uid=metadata["uid"], role="coordinator",
                record_path=metadata["record_path"], expected_record=metadata["record"],
                clock_domain=metadata["clock_domain"], captured_mono=metadata["captured_mono"],
                catalog_deadline=metadata["catalog_deadline"],
                assignment_deadline=metadata["assignment_deadline"], clock=clock,
                signed_catalog=signed_catalog, signed_assignment=signed_assignment,
                verifier=verifier)
            return ChildArtifactPinSet((owner,), (guard,))
        except BaseException as error:
            _attach_owner(error, owners)
            raise

    originals = (metadata["global_fd"], metadata["role_fd"])
    for index, (item, assignment_bytes) in enumerate(assignments):
        pair_owner = None
        pair = originals
        if index:
            global_copy = None
            try:
                global_copy = os.dup(originals[0])
                pair_owner = _owner_for_partial_pair(global_copy)
                role_copy = os.dup(originals[1])
                pair_owner.role_fd = role_copy
                pair_owner._close_outcomes["role_fd"] = "open"
                pair = (global_copy, role_copy)
            except BaseException as error:
                if pair_owner is not None:
                    try:
                        pair_owner.close_after_failed_acquire()
                    except BaseException as close_error:
                        _attach_owner(close_error, owners, pair_owner)
                        raise close_error from error
                _attach_owner(error, owners)
                raise
        try:
            owner, guard = validate_inherited_group_pin(
                pair[0], pair[1], root=metadata["root"], uid=metadata["uid"],
                record_path=metadata["record_path"], expected_record=metadata["record"],
                component=item["component"], worker_boot_id=item["worker_boot_id"],
                clock_domain=metadata["clock_domain"], captured_mono=metadata["captured_mono"],
                catalog_deadline=metadata["catalog_deadline"],
                assignment_deadline=item["assignment_deadline"], clock=clock,
                signed_catalog=signed_catalog, signed_assignment=assignment_bytes,
                verifier=verifier)
            owners.append(owner)
            guards.append(guard)
        except BaseException as error:
            # The validator either closed its current descriptors or attached
            # the exact uncertain cleanup owner. Never close the pair again.
            _attach_owner(error, owners)
            raise
    return ChildArtifactPinSet(tuple(owners), tuple(guards))

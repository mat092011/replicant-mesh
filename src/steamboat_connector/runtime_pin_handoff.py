"""Bounded child-side validation for supervisor-inherited artifact pins.

The fixed role adapter must call ``validate_child_pin`` after its startup gate
opens and before loading model artifacts. This helper does not create role
readiness or select a trust root: the adapter supplies the operator-approved
core Clock and CatalogVerifier.
"""

import base64
import binascii
import os
from dataclasses import dataclass

from steamboat_security.clock import Clock
from steamboat_connector.catalog import CatalogVerifier


class RuntimePinHandoffError(ValueError):
    """The child could not establish the inherited artifact ownership."""


@dataclass
class ChildArtifactPinSet:
    """Strongly retain validated child pin owners and assignment guards."""

    owners: tuple
    guards: tuple
    _closed: bool = False

    def close(self):
        if self._closed:
            return
        # Mark each owner closed itself; if one close is uncertain, retain the
        # remaining owners and make the aggregate close operation sticky.
        errors = []
        for owner in reversed(self.owners):
            try:
                owner.close()
            except Exception as error:
                errors.append(error)
        if errors:
            raise RuntimePinHandoffError("child artifact pin cleanup is uncertain") from errors[0]
        self._closed = True


def _decode(value, label):
    if type(value) is not str:
        raise RuntimePinHandoffError(f"{label} is malformed")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise RuntimePinHandoffError(f"{label} is malformed") from error


def validate_child_pin(metadata, *, clock, verifier):
    """Validate a closed supervisor pin document with trusted child objects.

    The FDs in ``metadata`` are accepted only as inherited ownership handles;
    the existing pin validators still bind them to locked store paths and
    signed records. Call this after the parent releases the startup gate.
    """
    if (type(metadata) is not dict or type(clock) is not Clock
            or type(verifier) is not CatalogVerifier or verifier.clock is not clock
            or type(metadata.get("role")) is not str
            or type(metadata.get("record")) is not dict
            or type(metadata.get("global_fd")) is not int
            or type(metadata.get("role_fd")) is not int
            or metadata["global_fd"] == metadata["role_fd"]):
        raise RuntimePinHandoffError("inherited pin inputs are malformed")
    if _decode(metadata.get("public_key"), "catalog trust key") != verifier.public_key:
        raise RuntimePinHandoffError("inherited pin trust key differs from adapter trust")

    from steamboat_connector.artifact_pin import validate_inherited_pin
    from steamboat_connector.aggregate_artifact_pin import validate_inherited_group_pin

    owners = []
    guards = []
    kind = metadata.get("kind")
    try:
        signed_catalog = _decode(metadata.get("signed_catalog"), "signed catalog")
        if kind == "single" and metadata["role"] == "coordinator":
            if set(metadata) != {
                    "version", "kind", "role", "root", "uid", "record_path", "record",
                    "global_fd", "role_fd", "clock_domain", "captured_mono",
                    "catalog_deadline", "assignment_deadline", "signed_catalog",
                    "signed_assignment", "public_key"} or metadata["version"] != 1:
                raise RuntimePinHandoffError("single pin metadata fields are not closed")
            signed_assignment = _decode(metadata.get("signed_assignment"),
                                         "signed assignment")
            owner, guard = validate_inherited_pin(
                metadata["global_fd"], metadata["role_fd"],
                root=metadata.get("root"), uid=metadata.get("uid"),
                role="coordinator", record_path=metadata.get("record_path"),
                expected_record=metadata["record"],
                clock_domain=metadata.get("clock_domain"),
                captured_mono=metadata.get("captured_mono"),
                catalog_deadline=metadata.get("catalog_deadline"),
                assignment_deadline=metadata.get("assignment_deadline"),
                clock=clock, signed_catalog=signed_catalog,
                signed_assignment=signed_assignment, verifier=verifier)
            owners.append(owner)
            guards.append(guard)
        elif kind == "group" and metadata["role"] == "host":
            if set(metadata) != {
                    "version", "kind", "role", "root", "uid", "record_path", "record",
                    "global_fd", "role_fd", "clock_domain", "captured_mono",
                    "catalog_deadline", "signed_catalog", "public_key", "assignments"} \
                    or metadata["version"] != 1:
                raise RuntimePinHandoffError("aggregate pin metadata fields are not closed")
            assignments = metadata.get("assignments")
            if type(assignments) is not list or not 1 <= len(assignments) <= 3:
                raise RuntimePinHandoffError("aggregate assignment list is outside its bound")
            if (len({item.get("component") for item in assignments
                     if type(item) is dict}) != len(assignments)):
                raise RuntimePinHandoffError("aggregate assignment components are duplicated")
            originals = (metadata["global_fd"], metadata["role_fd"])
            duplicates = []
            pending = set()
            try:
                for _ in assignments:
                    pair = (os.dup(originals[0]), os.dup(originals[1]))
                    duplicates.append(pair)
                    pending.update(pair)
                # The original inherited descriptors are transport handles only;
                # each validator owns a distinct descriptor pair from here on.
                for fd in originals:
                    os.set_inheritable(fd, False)
                    os.close(fd)
            except BaseException:
                for pair in duplicates:
                    for fd in pair:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                raise
            for item, pair in zip(assignments, duplicates):
                if type(item) is not dict:
                    raise RuntimePinHandoffError("aggregate assignment entry is malformed")
                signed_assignment = _decode(item.get("signed_assignment"),
                                             "signed assignment")
                pending.difference_update(pair)
                owner, guard = validate_inherited_group_pin(
                    pair[0], pair[1], root=metadata.get("root"),
                    uid=metadata.get("uid"), record_path=metadata.get("record_path"),
                    expected_record=metadata["record"],
                    component=item.get("component"),
                    worker_boot_id=item.get("worker_boot_id"),
                    clock_domain=metadata.get("clock_domain"),
                    captured_mono=metadata.get("captured_mono"),
                    catalog_deadline=metadata.get("catalog_deadline"),
                    assignment_deadline=item.get("assignment_deadline"),
                    clock=clock, signed_catalog=signed_catalog,
                    signed_assignment=signed_assignment, verifier=verifier)
                owners.append(owner)
                guards.append(guard)
        else:
            raise RuntimePinHandoffError("pin kind and role are unsupported")
        return ChildArtifactPinSet(tuple(owners), tuple(guards))
    except BaseException as error:
        for fd in locals().get("pending", ()):
            try:
                os.close(fd)
            except OSError:
                pass
        # Keep any successfully validated owners reachable when a later
        # component fails; the process must not silently drop lock ownership.
        if owners:
            error.pin_owner = ChildArtifactPinSet(tuple(owners), tuple(guards))
        raise

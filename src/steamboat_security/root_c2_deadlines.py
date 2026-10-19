"""Binding-local retention of signed authorization deadline observations.

SnapshotStore clips each view for the uncertainty of the sample that produced
it. This helper keeps earlier, tighter monotonic bounds across later samples
and policy-head observations without acquiring storage or SnapshotStore locks.
It creates no identity or authorization evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
from types import MappingProxyType

from .clock import ClockSample
from .errors import SnapshotError
from .snapshot import CredentialRecord, Grant, SnapshotStore, SnapshotView

MAX_POLICY_FLOORS = 64
MAX_CREDENTIAL_FLOORS = 512
MAX_GRANT_FLOORS = 2048


def _credential_key(serial, record):
    return (serial, record.account_id, record.device_id, record.role,
            record.credential_epoch, record.certificate_sha256,
            record.public_key_sha256)


@dataclass
class DeadlineFloors:
    """Small, binding-owned monotonic floors; caller serializes access by lock."""

    policy: dict[int, float] = field(default_factory=dict)
    credentials: dict[tuple, float] = field(default_factory=dict)
    grants: dict[tuple, float] = field(default_factory=dict)

    def retain(self, view: SnapshotView, sample: ClockSample) -> SnapshotView:
        if (type(self) is not DeadlineFloors or type(view) is not SnapshotView
                or type(sample) is not ClockSample):
            raise SnapshotError("deadline retention requires verified snapshot view and exact clock sample")
        if (type(view.expires_at) is not int or type(view.deadline_monotonic) not in (int, float)
                or not math.isfinite(view.deadline_monotonic)
                or any(type(value) is not float or not math.isfinite(value)
                       for value in (sample.wall, sample.monotonic, sample.uncertainty))):
            raise SnapshotError("snapshot deadline fields are malformed")
        if type(self.policy) is not dict or type(self.credentials) is not dict or type(self.grants) is not dict:
            raise SnapshotError("binding deadline floor state is malformed")
        limits = ((self.policy, MAX_POLICY_FLOORS),
                  (self.credentials, MAX_CREDENTIAL_FLOORS),
                  (self.grants, MAX_GRANT_FLOORS))
        if any(len(values) > bound for values, bound in limits):
            raise SnapshotError("binding deadline floor history exceeds its fixed bound")
        if any(type(value) is not float or not math.isfinite(value)
               for values, _bound in limits for value in values.values()):
            raise SnapshotError("binding deadline floor contains a malformed value")

        clipped = SnapshotStore._clip_prepared_view(view, sample)
        expiry = view.expires_at
        if expiry not in self.policy and len(self.policy) >= MAX_POLICY_FLOORS:
            raise SnapshotError("binding policy deadline history is full; cold restart required")
        policy_deadline = min(self.policy.get(expiry, clipped.deadline_monotonic),
                              clipped.deadline_monotonic)
        self.policy[expiry] = policy_deadline

        if type(view.credentials_by_serial) is not dict and not hasattr(view.credentials_by_serial, "items"):
            raise SnapshotError("snapshot credential map is malformed")
        if type(view.grants) is not tuple:
            raise SnapshotError("snapshot grant collection is malformed")
        credential_deadlines = {}
        for serial, record in view.credentials_by_serial.items():
            if (type(serial) is not str or type(record) is not CredentialRecord
                    or serial not in clipped.credential_deadlines):
                raise SnapshotError("snapshot credential entry is malformed")
            key = _credential_key(serial, record)
            if key not in self.credentials and len(self.credentials) >= MAX_CREDENTIAL_FLOORS:
                raise SnapshotError("binding credential deadline history is full; cold restart required")
            deadline = min(self.credentials.get(key, clipped.credential_deadlines[serial]),
                           clipped.credential_deadlines[serial])
            self.credentials[key] = deadline
            credential_deadlines[serial] = deadline

        grant_deadlines = {}
        for grant in view.grants:
            if type(grant) is not Grant or grant.identity not in clipped.grant_deadlines:
                raise SnapshotError("snapshot grant entry is malformed")
            key = grant.identity
            if type(key) is not tuple:
                raise SnapshotError("snapshot grant identity is malformed")
            if key not in self.grants and len(self.grants) >= MAX_GRANT_FLOORS:
                raise SnapshotError("binding grant deadline history is full; cold restart required")
            deadline = min(self.grants.get(key, clipped.grant_deadlines[key]),
                           clipped.grant_deadlines[key])
            self.grants[key] = deadline
            grant_deadlines[key] = deadline

        return replace(clipped, deadline_monotonic=policy_deadline,
            credential_deadlines=MappingProxyType(credential_deadlines),
            grant_deadlines=MappingProxyType(grant_deadlines))

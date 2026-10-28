"""Detector registry: built-ins plus third-party plugins (entry point group sshleak.detectors)."""

from __future__ import annotations

from importlib.metadata import entry_points

from sshleak.detectors.base import Detector
from sshleak.detectors.l01_timing_unprotected import L1TimingUnprotected
from sshleak.detectors.l02_obfuscation_inactive import L2ObfuscationInactive
from sshleak.detectors.l03_chaff_distinguishable import L3ChaffDistinguishable
from sshleak.detectors.l04_password_pattern import L4PasswordPattern
from sshleak.detectors.l05_keystroke_count import L5KeystrokeCount
from sshleak.detectors.l06_command_boundary import L6CommandBoundary
from sshleak.detectors.l07_residual_timing import L7ResidualTiming
from sshleak.detectors.l08_obfuscation_cost import L8ObfuscationCost
from sshleak.detectors.l09_compression import L9Compression
from sshleak.detectors.l10_weak_algorithms import L10WeakAlgorithms
from sshleak.detectors.l11_client_lacks_feature import L11ClientLacksFeature
from sshleak.detectors.l12_session_type import L12SessionType
from sshleak.detectors.l13_observation_hop import L13ObservationHop

BUILTIN: tuple[type[Detector], ...] = (
    L1TimingUnprotected, L2ObfuscationInactive, L3ChaffDistinguishable, L4PasswordPattern,
    L5KeystrokeCount, L6CommandBoundary, L7ResidualTiming, L8ObfuscationCost, L9Compression,
    L10WeakAlgorithms, L11ClientLacksFeature, L12SessionType, L13ObservationHop,
)


def _sort_key(det_id: str) -> tuple:
    head = det_id.rstrip("0123456789")
    tail = det_id[len(head):]
    return (head, int(tail) if tail else 0)


def load_detectors(include_plugins: bool = True) -> list[Detector]:
    dets: dict[str, Detector] = {cls.meta.id: cls() for cls in BUILTIN}
    if include_plugins:
        for ep in entry_points(group="sshleak.detectors"):
            cls = ep.load()
            inst = cls()
            if inst.meta.id in dets:
                raise ValueError(f"plugin {ep.name} reuses detector id {inst.meta.id}")
            dets[inst.meta.id] = inst
    return [dets[k] for k in sorted(dets, key=_sort_key)]


def detector_ids() -> list[str]:
    return [d.meta.id for d in load_detectors(include_plugins=False)]

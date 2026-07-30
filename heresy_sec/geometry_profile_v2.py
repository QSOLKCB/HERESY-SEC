"""Deterministic profile-v2 resolver for Forman limits and failure modes.

This additive dispatcher preserves ``heresy-geom.profile/v1`` unchanged and installs
the indivisible ``heresy-geom.profile/v2`` Forman-resolution package.
"""

from __future__ import annotations

from typing import Any

from . import artifacts as _artifacts
from . import geometry as _geometry
from .geometry_profile_v2_policy import (
    FIXTURE_SET_V2,
    PROFILE_V2,
    build_forman_curvature_v2,
    default_forman_resolve_policy,
    normalize_geometry_policy,
)
from .geometry_profile_v2_runtime import (
    build_geometry_windows,
    geometry_artifact_map,
    install_engine_dispatch,
)


_INSTALLED = False


def install_profile_v2() -> None:
    """Install the profile dispatcher before contracts and engine bind imports."""

    global _INSTALLED
    if _INSTALLED:
        return
    _geometry.normalize_geometry_policy = normalize_geometry_policy
    _geometry.build_geometry_windows = build_geometry_windows
    _geometry.geometry_artifact_map = geometry_artifact_map
    _geometry.PROFILE_V2 = PROFILE_V2
    _geometry.FIXTURE_SET_V2 = FIXTURE_SET_V2
    _geometry.default_forman_resolve_policy = default_forman_resolve_policy
    _geometry.build_forman_curvature_v2 = build_forman_curvature_v2
    _artifacts.README_ORIGIN_V2 = (
        b"HERESY-SEC deterministic policy and geometric evidence run.\n"
        b"Created by HERESY-SEC v0.3.0 under heresy-sec.policy/v2.\n"
        b"The exact geometry profile is pinned in policy.json and summary.json.\n"
        b"No proposed action was executed by this evidence engine.\n"
    )
    _INSTALLED = True


__all__ = [
    "FIXTURE_SET_V2",
    "PROFILE_V2",
    "build_forman_curvature_v2",
    "default_forman_resolve_policy",
    "install_engine_dispatch",
    "install_profile_v2",
]

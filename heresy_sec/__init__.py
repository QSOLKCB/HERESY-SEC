"""HERESY-SEC deterministic evidence and policy engine."""

from __future__ import annotations


__version__ = "0.3.0"

from .geometry_profile_v2 import (  # noqa: E402
    install_engine_dispatch as _install_engine_dispatch,
    install_profile_v2 as _install_profile_v2,
)

_install_profile_v2()

from . import engine as _engine  # noqa: E402

_install_engine_dispatch(_engine)

del _engine, _install_engine_dispatch, _install_profile_v2

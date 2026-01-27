from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.domain.policy import Policy
from app.domain.policy_loader import PolicyLoadError, load_policy_from_file


class PolicyProviderError(RuntimeError):
    pass


@dataclass
class PolicyProvider:
    """
    Loads the active policy from a file path supplied via env var.

    Design notes:
    - This is a provider, not a registry. v0 assumes a single active policy.
    - Reload uses mtime checks (opt-in) to balance correctness and simplicity.
    """
    policy_path: Path
    reload_enabled: bool = True
    min_mtime_interval_s: float = 0.5

    _cached_policy: Optional[Policy] = None
    _cached_mtime: Optional[float] = None
    _last_stat_at: float = 0.0

    def get(self) -> Policy:
        if not self.policy_path:
            raise PolicyProviderError("policy_path is required")

        if not self.reload_enabled:
            if self._cached_policy is None:
                self._cached_policy = self._load()
            return self._cached_policy

        # Reload-enabled: use mtime checks with a small throttle
        now = time.monotonic()
        if (now - self._last_stat_at) < self.min_mtime_interval_s and self._cached_policy is not None:
            return self._cached_policy
        self._last_stat_at = now

        try:
            mtime = self.policy_path.stat().st_mtime
        except OSError as e:
            raise PolicyProviderError(f"Cannot stat policy file: {self.policy_path}") from e

        if self._cached_policy is None or self._cached_mtime is None or mtime != self._cached_mtime:
            self._cached_policy = self._load()
            self._cached_mtime = mtime

        return self._cached_policy

    def _load(self) -> Policy:
        try:
            return load_policy_from_file(self.policy_path)
        except PolicyLoadError as e:
            raise PolicyProviderError(f"Failed to load policy from {self.policy_path}: {e}") from e


def policy_provider_from_env() -> PolicyProvider:
    path = os.getenv("AUTHZ_POLICY_PATH")
    if not path:
        raise PolicyProviderError("AUTHZ_POLICY_PATH must be set (path to policy JSON file)")

    reload_enabled = os.getenv("AUTHZ_POLICY_RELOAD", "1").strip() != "0"
    min_mtime_interval_s = float(os.getenv("AUTHZ_POLICY_MIN_MTIME_S", "0.5"))

    return PolicyProvider(
        policy_path=Path(path),
        reload_enabled=reload_enabled,
        min_mtime_interval_s=min_mtime_interval_s,
    )

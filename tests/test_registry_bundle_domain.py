from __future__ import annotations

import unittest

from heresy_sec.geometry_profile_v2_policy import _V2_DOMAINS
from heresy_sec.geometry_profile_v2_sensors import _REGISTRY_BUNDLE_DOMAIN


class RegistryBundleDomainTests(unittest.TestCase):
    def test_aggregate_registry_has_distinct_hash_domain(self) -> None:
        self.assertEqual(
            _REGISTRY_BUNDLE_DOMAIN,
            "HERESY-GEOM/IMPOSSIBLE-CONFIGURATIONS-BUNDLE/v2",
        )
        self.assertNotEqual(_REGISTRY_BUNDLE_DOMAIN, _V2_DOMAINS["registry"])


if __name__ == "__main__":
    unittest.main()

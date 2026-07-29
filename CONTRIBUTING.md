# Contributing

Contributions should keep HERESY-SEC small, deterministic and side-effect-free.

1. Create a focused branch.
2. Add or update tests for every identity or policy change.
3. Run every quality gate listed in the README.
4. Document schema compatibility and security impact.
5. Open a pull request with reproducible evidence.

Identity-bearing byte changes require explicit review because they can break exact
replay. New adapters must translate bounded evidence without silently granting
authority.


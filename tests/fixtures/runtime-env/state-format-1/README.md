# State format 1 fixture

A state directory exactly as the protocol-v1 POC helper (commit ce319e4) wrote it: one flake-provenance generation and one import generation, both applied, so `current` selects the import generation with the flake generation as previous. Store paths are fictional and the archives use the unit-test store's `archive:` layout.

Do not regenerate or edit it. Guest image pins are write-once and the Upgrade-image swap keeps the pool, so state outlives the helper that wrote it: every future helper must keep parsing this tree (`tests/test_runtime_env.py`, `StateFormatOneTest`).

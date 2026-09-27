# Contributing to AIP Judgment Sidecar

This repository maintains an independent AIP receipt prototype. It does not
implement JEP Core wire events or define a JEP reference implementation.
See the [receipt and key boundaries](README.md#receipt-and-key-boundaries).

Install and test changes from the repository root:

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

Keep receipt format/version, canonicalization, key trust and application policy
explicit. Preserve historical signed bytes and require explicit compatibility
selection. A valid receipt signature does not authenticate an AAT token or grant
permission to execute a tool.

For signed J/D/T/V events, use [JEP Core](https://github.com/hjs-spec/jep-core)
and the maintained [integration directory](https://github.com/hjs-spec/.github/blob/main/PROJECTS.md#integrate).

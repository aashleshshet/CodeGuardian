# Reproducible scan fixtures

`baseline/` and `current/` are two source snapshots, not runnable applications.
The baseline additionally uses unsafe pickle deserialization and weak cryptographic hashing.
The current snapshot removes those examples so commit comparisons have real resolved findings.
Neither directory has a package manifest, install hook, or executable test command.

Generate actual scanner results with `python scripts/build_demo.py` after installing the backend
requirements and putting the virtual environment's bin directory on PATH. Results include scanner
versions, timestamps and content hashes; they do not claim to be Git commit SHAs.

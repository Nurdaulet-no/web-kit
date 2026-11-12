Inactive source archive

incoming-only/ contains files absent from the main project.
conflicting-versions/ contains imported versions differing from the main project.
manifest.json maps every original file to its retained copy and SHA-256 hash.
Identical files were retained in the main project instead of duplicated here.

orphaned-tests/ preserves tests for coding_agent.py, which was already absent
when this cleanup started. These tests are not application tests.

Files are preserved as data, without enabling or repairing attack functionality.
Some archived source files contain syntax errors. Run and test the application
from the repository root using audit.py, auditkit/ and tests/.

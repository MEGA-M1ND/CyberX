# Fixture output

Empty by design. This directory is populated only by a real lab run: the provisioner writes what
each fixture actually looked like on the machine after it was created, and the collectors' raw
JSON lands here alongside it.

The fixture *specifications* are code (`src/rv3/fixtures/catalog.py`), and their frozen hashes are
in `manifests/fixture-manifest.json`. Nothing here is needed to reproduce the dry-run analysis.

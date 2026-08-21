import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def catalog():
    from rv3.fixtures.catalog import build_catalog
    return build_catalog()


@pytest.fixture(scope="session")
def classifications(catalog):
    from rv3.analysis.classify import classify_predicted
    from rv3.contracts.catalog import ALL_CONTRACTS
    return classify_predicted(catalog, [c.collector_id for c in ALL_CONTRACTS])

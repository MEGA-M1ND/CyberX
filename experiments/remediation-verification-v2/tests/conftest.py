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
def dev_conditions():
    from rv2.bench.generate import generate
    return generate("dev")


@pytest.fixture(scope="session")
def scored_dev():
    """One full dev-partition run, shared across the session."""
    from rv2.bench.run import run_partition
    return run_partition(ROOT, "dev")

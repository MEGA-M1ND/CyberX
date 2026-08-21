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
def corpus():
    from rvbench.corpus.build import build
    return build()


@pytest.fixture(scope="session")
def by_id(corpus):
    return {c["public"]["case_id"]: c for c in corpus}


@pytest.fixture(scope="session")
def experiment(root):
    """Runs the full experiment once for the whole session."""
    from rvbench.runner import run
    return run(root)

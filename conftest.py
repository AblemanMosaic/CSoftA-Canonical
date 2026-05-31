"""
Root conftest.py for CSoftA gate test suite.

Adds each system's impl/ directory to sys.path so EAR adapters import correctly.
This is needed because all 80 test files share the name test_gate_suite.py and
each imports from its own co-located adapter.
"""
import sys
import pathlib

_repo_root = pathlib.Path(__file__).parent

for _sdir in sorted(_repo_root.iterdir()):
    _impl = _sdir / "impl"
    if _impl.is_dir() and (_sdir / "impl" / "tests" / "test_gate_suite.py").exists():
        _impl_str = str(_impl)
        if _impl_str not in sys.path:
            sys.path.insert(0, _impl_str)

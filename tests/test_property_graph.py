import json
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PYTHON_DIR = os.path.join(ROOT_DIR, "python")
if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sharplogic import Autoformalizer, RustSharpLogicEngine  # noqa: E402


class TestPropertyGraph(unittest.TestCase):
    def test_engine_handles_empty_clause(self):
        eng = RustSharpLogicEngine(force_serverless=True)
        try:
            res = eng.solve_cnf(2, [[]], [0.5, 0.5])
            self.assertEqual(res["exact_count"], 0)
        finally:
            eng.close()


if __name__ == "__main__":
    unittest.main()
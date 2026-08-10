"""Test suite for Anthropic Safety Monitor Action Boundary Checker."""
import unittest

class ActionBoundaryCheckerSim:
    def __init__(self, max_mutations: int):
        self.max_mutations = max_mutations
        self.count = 0

    def validate_action(self, action: str) -> bool:
        if action in ["delete_root", "hard_reset"]:
            return False
        self.count += 1
        return self.count <= self.max_mutations

class TestActionBoundaryChecker(unittest.TestCase):
    def test_forbidden_action(self):
        c = ActionBoundaryCheckerSim(max_mutations=5)
        self.assertFalse(c.validate_action("delete_root"))
        self.assertTrue(c.validate_action("view_file"))

if __name__ == "__main__":
    unittest.main()

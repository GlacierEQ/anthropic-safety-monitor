import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from safety_monitor import ToolCall, evaluate

def test_deny_rm():
    assert evaluate(ToolCall("bash", "rm -rf /"))["decision"] == "deny"

def test_allow_ls():
    assert evaluate(ToolCall("bash", "ls"))["decision"] == "allow"

def test_confirm_force_push():
    assert evaluate(ToolCall("bash", "git push --force origin x"))["decision"] == "confirm"

if __name__ == "__main__":
    test_deny_rm(); test_allow_ls(); test_confirm_force_push(); print("ok")

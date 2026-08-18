import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_DIR = "/mnt/us/kindle_hid_passthrough/"


def _actions(items):
    for item in items:
        if "action" in item:
            yield item["action"]
        yield from _actions(item.get("items", []))


def test_kual_actions_exist_in_the_release():
    menu = json.loads((REPO / "assets" / "menu.json").read_text())
    actions = list(_actions(menu["items"]))
    assert actions
    for action in actions:
        assert action.startswith(INSTALL_DIR), action
        target = REPO / action[len(INSTALL_DIR) :]
        assert target.is_file(), action
        assert target.stat().st_mode & 0o111, f"{action} is not executable"

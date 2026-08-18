import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_DIR = "/mnt/us/kindle_hid_passthrough/"


def _actions(items):
    for item in items:
        if "action" in item:
            yield item["action"], item.get("params", "")
        yield from _actions(item.get("items", []))


def _menu():
    out = subprocess.run(
        ["sh", "scripts/install.sh", "kualMenu"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


def test_kual_actions_exist_in_the_release():
    actions = list(_actions(_menu()["items"]))
    assert actions
    for action, _ in actions:
        assert action.startswith(INSTALL_DIR), action
        target = REPO / action[len(INSTALL_DIR) :]
        assert target.is_file(), action
        assert target.stat().st_mode & 0o111, f"{action} is not executable"


def test_kual_params_are_accepted_actions():
    installer = (REPO / "scripts" / "install.sh").read_text()
    dispatcher = installer.split("if [ $# -gt 0 ]; then")[1].split("esac")[0]
    accepted = set(re.findall(r"[A-Za-z]\w+(?=\s*[|)])", dispatcher))
    offered = {
        line.split("|")[0]
        for line in installer.split('MENU="')[1].split('"')[0].splitlines()
    }
    for action, params in _actions(_menu()["items"]):
        if not action.endswith("install.sh"):
            continue
        entry, _, argument = params.partition(" ")
        assert entry in accepted, params
        assert argument in offered, params

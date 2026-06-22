"""Supply-chain module: vulnerable deps + secrets in git history."""
import subprocess
from pathlib import Path

from hacker.models import Severity, ThreatClass
from hacker.modules import supplychain

VULN_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_app")
HARD_REPO = str(Path(__file__).parent / "fixtures" / "hardened_app")


def test_flags_vulnerable_dependency_offline():
    findings = supplychain.run_static(VULN_REPO, offline=True)
    deps = [f for f in findings if f.title.startswith("Vulnerable dependency")]
    assert any("pyyaml" in f.title for f in deps)
    assert any(f.severity == Severity.CRITICAL for f in deps)  # pyyaml CVE is critical


def test_patched_dependencies_clean_offline():
    findings = supplychain.run_static(HARD_REPO, offline=True)
    deps = [f for f in findings if f.title.startswith("Vulnerable dependency")]
    assert deps == [], [f.title for f in deps]


def test_offline_makes_no_network_call(monkeypatch):
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("network call in offline mode")

    monkeypatch.setattr(supplychain, "_query_osv", _boom)
    supplychain.run_static(VULN_REPO, offline=True)
    assert called["n"] == 0


def test_finds_secret_removed_from_git_history(tmp_path):
    repo = tmp_path / "proj"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=True, text=True)

    git("init")
    git("config", "user.email", "t@t.test")
    git("config", "user.name", "t")

    secret_file = repo / "config.py"
    secret_file.write_text('API_KEY = "sk-abcdefghij1234567890ABCDEFGHIJ1234567890"\n')
    git("add", "-A")
    git("commit", "-m", "add config")

    # Remove the secret in a later commit — gone from the working tree, kept in history.
    secret_file.write_text("API_KEY = os.environ['API_KEY']\n")
    git("add", "-A")
    git("commit", "-m", "use env")

    findings = supplychain.run_static(str(repo), offline=True)
    hist = [f for f in findings if "git history" in f.title]
    assert hist, "expected a git-history secret finding"
    assert hist[0].threat_class == ThreatClass.SUPPLY_CHAIN


def test_non_git_dir_history_is_noop(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0.1\n")
    findings = supplychain.run_static(str(tmp_path), offline=True)
    assert all("git history" not in f.title for f in findings)

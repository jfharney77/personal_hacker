from hacker.recon import run_recon


def test_recon_enumerates_endpoints(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    assert recon.reachable
    paths = {e.path for e in recon.endpoints}
    assert "/users" in paths
    assert "/chat" in paths


def test_recon_detects_llm_endpoint(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    llm_paths = {e.path for e in recon.llm_endpoints()}
    assert "/chat" in llm_paths


def test_recon_captures_params(local_scope, vuln_client):
    recon = run_recon(local_scope, "http://localhost", client=vuln_client)
    users = next(e for e in recon.endpoints if e.path == "/users")
    assert "name" in users.params

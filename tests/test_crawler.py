"""HTML/route crawler + POST-body injection."""
from hacker.config import Scope
from hacker.models import Severity
from hacker.modules import dbinjection
from hacker.recon import _LinkFormParser, _same_origin_path, run_recon


def _scope():
    return Scope(allowlist=["localhost"], target_urls=["http://localhost"])


def test_parser_extracts_links_and_forms():
    p = _LinkFormParser()
    p.feed('<a href="/a">x</a><form action="/post" method="post">'
           '<input name="q"><textarea name="body"></textarea></form>')
    assert "/a" in p.links
    assert p.forms == [("/post", "post", ["q", "body"])]


def test_same_origin_filtering():
    base = "http://localhost"
    assert _same_origin_path(base, base + "/", "/users?x=1") == "/users?x=1"
    assert _same_origin_path(base, base + "/", "https://evil.com/x") is None
    assert _same_origin_path(base, base + "/", "javascript:alert(1)") is None
    assert _same_origin_path(base, base + "/", "mailto:a@b.c") is None


def test_recon_discovers_crawled_endpoints(vuln_client):
    recon = run_recon(_scope(), "http://localhost", client=vuln_client)
    by_path = {(e.method, e.path): e for e in recon.endpoints}
    # Anchor-only route, not in OpenAPI, found purely by crawling.
    assert ("GET", "/legacy") in by_path
    assert by_path[("GET", "/legacy")].source == "crawl"
    assert "id" in by_path[("GET", "/legacy")].params
    # The POST form target is present (merged with OpenAPI's view of it).
    assert ("POST", "/api/find") in by_path


def test_post_body_sql_injection_detected(vuln_client):
    recon = run_recon(_scope(), "http://localhost", client=vuln_client)
    findings = dbinjection.run_dynamic(_scope(), recon, vuln_client)
    post_sqli = [f for f in findings if "POST" in (f.evidence or "") and f.severity == Severity.CRITICAL]
    assert post_sqli, "expected a POST-body SQL injection finding on /api/find"

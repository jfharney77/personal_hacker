"""The safety core is the highest-stakes code in the tool — test it hard."""
import pytest

from hacker.config import Scope, ScopeError


def test_allowlisted_local_host_is_permitted():
    scope = Scope(allowlist=["localhost"], target_urls=["http://localhost:8000"])
    assert scope.guard("http://localhost:8000/users") == "http://localhost:8000/users"


def test_unlisted_host_is_refused():
    scope = Scope(allowlist=["localhost"])
    with pytest.raises(ScopeError, match="not in scope allowlist"):
        scope.guard("http://evil.example.com/")


def test_public_host_requires_ownership_flag():
    scope = Scope(allowlist=["myapp.com"])
    with pytest.raises(ScopeError, match="i_own_this"):
        scope.guard("https://myapp.com/login")


def test_public_host_allowed_with_ownership_flag():
    scope = Scope(allowlist=["myapp.com"], i_own_this=True)
    assert scope.guard("https://myapp.com/login")


def test_private_ip_is_treated_as_local():
    scope = Scope(allowlist=["10.0.0.5"])
    # private IPs don't need i_own_this
    assert scope.guard("http://10.0.0.5:8000/")


def test_validate_self_rejects_target_off_allowlist():
    scope = Scope(allowlist=["localhost"], target_urls=["http://other:9000"])
    with pytest.raises(ScopeError, match="not on the allowlist"):
        scope.validate_self()


def test_safe_mode_defaults_on():
    assert Scope(allowlist=["localhost"]).safe_mode is True

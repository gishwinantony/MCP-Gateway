from __future__ import annotations

import hashlib

from mcpgateway.policy import (
    ArgumentGuard,
    Decision,
    PolicyEngine,
    Principal,
    RateLimit,
    TokenBucket,
)


def principal(**kwargs) -> Principal:
    defaults = {
        "id": "dev",
        "token_sha256": hashlib.sha256(b"secret").hexdigest(),
        "allow": ["files__*"],
        "deny": ["files__delete_*"],
    }
    defaults.update(kwargs)
    return Principal(**defaults)


def test_authenticate_matches_hashed_token():
    engine = PolicyEngine([principal()])
    assert engine.authenticate("secret").id == "dev"
    assert engine.authenticate("wrong") is None
    assert engine.authenticate(None) is None


def test_deny_beats_allow():
    engine = PolicyEngine([principal()])
    subject = engine.principals["dev"]
    assert engine.check_call(subject, "files__read_file", {}).allowed
    denied = engine.check_call(subject, "files__delete_file", {})
    assert denied.decision is Decision.DENY
    assert "deny rule" in denied.reason


def test_tools_outside_allow_list_are_invisible():
    engine = PolicyEngine([principal()])
    subject = engine.principals["dev"]
    visible = engine.visible_tools(subject, ["files__read_file", "stripe__refund"])
    assert visible == ["files__read_file"]
    assert engine.check_call(subject, "stripe__refund", {}).decision is Decision.DENY


def test_argument_guard_blocks_sensitive_paths():
    guard = ArgumentGuard(tool="files__read_file", field="path", deny_regex=r"/\.ssh/|(^|/)\.env$")
    engine = PolicyEngine([principal(argument_guards=[guard])])
    subject = engine.principals["dev"]
    assert engine.check_call(subject, "files__read_file", {"path": "notes.md"}).allowed
    blocked = engine.check_call(subject, "files__read_file", {"path": "/home/x/.ssh/id_rsa"})
    assert blocked.decision is Decision.DENY
    assert "denied pattern" in blocked.reason


def test_argument_guard_reads_nested_fields():
    guard = ArgumentGuard(tool="*", field="options.target", deny_regex="prod")
    engine = PolicyEngine([principal(allow=["*"], deny=[], argument_guards=[guard])])
    subject = engine.principals["dev"]
    assert not engine.check_call(subject, "k8s__scale", {"options": {"target": "prod-a"}}).allowed
    assert engine.check_call(subject, "k8s__scale", {"options": {"target": "stg-a"}}).allowed


def test_rate_limit_trips_then_refills():
    engine = PolicyEngine(
        [principal(rate_limit=RateLimit(calls_per_minute=60, burst=3))]
    )
    subject = engine.principals["dev"]
    now = 1000.0
    for _ in range(3):
        assert engine.check_call(subject, "files__read_file", {}, now=now).allowed
    limited = engine.check_call(subject, "files__read_file", {}, now=now)
    assert limited.decision is Decision.RATE_LIMITED
    # 60 calls/minute means one token per second.
    assert engine.check_call(subject, "files__read_file", {}, now=now + 1.1).allowed


def test_per_tool_rate_limit_is_independent():
    engine = PolicyEngine(
        [
            principal(
                allow=["files__*"],
                deny=[],
                rate_limit=RateLimit(calls_per_minute=6000, burst=100),
                per_tool_rate_limit=RateLimit(calls_per_minute=60, burst=1),
            )
        ]
    )
    subject = engine.principals["dev"]
    now = 500.0
    assert engine.check_call(subject, "files__read_file", {}, now=now).allowed
    assert engine.check_call(subject, "files__read_file", {}, now=now).decision is (
        Decision.RATE_LIMITED
    )
    assert engine.check_call(subject, "files__write_file", {}, now=now).allowed


def test_require_approval_blocks_until_granted():
    engine = PolicyEngine([principal(allow=["*"], deny=[], require_approval=["*__delete_*"])])
    subject = engine.principals["dev"]
    pending = engine.check_call(subject, "files__delete_file", {})
    assert pending.decision is Decision.NEEDS_APPROVAL
    engine.grant_approval("dev", "files__delete_file")
    assert engine.check_call(subject, "files__delete_file", {}).allowed


def test_token_bucket_never_exceeds_capacity():
    bucket = TokenBucket(capacity=5, rate_per_minute=6000)
    assert bucket.consume(now=0.0)
    assert bucket.available <= 5
    bucket.consume(now=100.0)
    assert bucket.available <= 5

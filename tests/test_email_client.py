"""Tests for web/services/email_client.py's SMTP-based
send_license_email(). No real network calls — smtplib.SMTP is monkeypatched
with a fake context manager, same monkeypatch-the-client convention as
tests/test_nowpayments_payment_flow.py's _FakeAsyncClient.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import web.services.email_client as email_client
from web.services.email_client import EmailDeliveryError, send_license_email


def _run(coro):
    return asyncio.run(coro)


class _FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.starttls_called = False
        self.login_args = None
        self.sendmail_args = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.starttls_called = True

    def login(self, username, password):
        self.login_args = (username, password)

    def sendmail(self, from_addr, to_addrs, msg):
        self.sendmail_args = (from_addr, to_addrs, msg)


@pytest.fixture(autouse=True)
def _clear_fake_smtp_instances():
    _FakeSMTP.instances.clear()
    yield
    _FakeSMTP.instances.clear()


@pytest.fixture
def smtp_env(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "bot@example.test")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.test")
    monkeypatch.setenv("SMTP_FROM_NAME", "OPTISEC")


class TestSendLicenseEmailSuccess:
    def test_success_sends_via_smtp_with_correct_recipient_and_body(self, smtp_env, monkeypatch):
        monkeypatch.setattr(email_client.smtplib, "SMTP", _FakeSMTP)

        _run(send_license_email("buyer@example.com", "OPS4-PRO-abc123.deadbeef", "OPTISEC Recon Pro"))

        assert len(_FakeSMTP.instances) == 1
        server = _FakeSMTP.instances[0]
        assert server.host == "smtp.example.test"
        assert server.port == 587
        assert server.starttls_called is True
        assert server.login_args == ("bot@example.test", "app-password")

        from_addr, to_addrs, msg = server.sendmail_args
        assert from_addr == "noreply@example.test"
        assert to_addrs == ["buyer@example.com"]
        assert "OPS4-PRO-abc123.deadbeef" in msg
        assert "OPTISEC Recon Pro" in msg

    def test_default_product_name_used_when_omitted(self, smtp_env, monkeypatch):
        monkeypatch.setattr(email_client.smtplib, "SMTP", _FakeSMTP)
        _run(send_license_email("buyer@example.com", "OPS4-PRO-xyz"))
        _, _, msg = _FakeSMTP.instances[0].sendmail_args
        assert "OPTISEC Recon Pro" in msg


class TestSendLicenseEmailFailure:
    def test_missing_config_raises_email_delivery_error(self, monkeypatch):
        for var in ("SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM_EMAIL"):
            monkeypatch.delenv(var, raising=False)

        with pytest.raises(EmailDeliveryError, match="not configured"):
            _run(send_license_email("buyer@example.com", "OPS4-PRO-abc"))

    def test_smtp_exception_wrapped_as_email_delivery_error(self, smtp_env, monkeypatch):
        import smtplib as real_smtplib

        class _RaisingSMTP(_FakeSMTP):
            def login(self, username, password):
                raise real_smtplib.SMTPAuthenticationError(535, b"bad credentials")

        monkeypatch.setattr(email_client.smtplib, "SMTP", _RaisingSMTP)

        with pytest.raises(EmailDeliveryError, match="SMTP send failed"):
            _run(send_license_email("buyer@example.com", "OPS4-PRO-abc"))

    def test_os_error_wrapped_as_email_delivery_error(self, smtp_env, monkeypatch):
        class _UnreachableSMTP(_FakeSMTP):
            def __init__(self, *a, **kw):
                raise OSError("connection refused")

        monkeypatch.setattr(email_client.smtplib, "SMTP", _UnreachableSMTP)

        with pytest.raises(EmailDeliveryError, match="SMTP send failed"):
            _run(send_license_email("buyer@example.com", "OPS4-PRO-abc"))

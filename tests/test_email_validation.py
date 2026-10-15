from typing import Optional

import pytest
from pydantic import EmailStr, ValidationError

from web.schemas import CveDraftRequest, RegisterRequest, UserDetail

VALID = {"username": "analyst1", "password": "StrongPass1!"}


def test_register_accepts_valid_email():
    m = RegisterRequest(email="analyst@optisec.io", **VALID)
    assert m.email == "analyst@optisec.io"


@pytest.mark.parametrize("bad", ["not-an-email", "a@", "@x.com", "a b@x.com"])
def test_register_rejects_invalid_email(bad):
    with pytest.raises(ValidationError) as exc:
        RegisterRequest(email=bad, **VALID)
    assert any(e["loc"] == ("email",) for e in exc.value.errors())


def test_cve_reporter_email_is_validated_type():
    assert CveDraftRequest.model_fields["reporter_email"].annotation == Optional[EmailStr]


def test_user_detail_output_stays_lenient():
    assert UserDetail.model_fields["email"].annotation is str

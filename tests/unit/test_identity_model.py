"""Unit tests for the ClientIdentity Pydantic model and email validation."""

import pytest
from pydantic import ValidationError

from envoy_authz.identity import ClientIdentity, _validate_email


def test_empty_model_is_all_optional():
    identity = ClientIdentity()
    assert identity.common_name is None
    assert identity.organizational_units == []
    assert identity.additional_email_addresses == []
    assert identity.key_usages == []
    assert identity.is_ca is None


def test_valid_fields_accepted_and_stripped():
    identity = ClientIdentity(
        common_name="  Jane Doe  ",
        organization="ACME",
        organizational_units=["eng", "sre"],
        uid="jdoe",
    )
    assert identity.common_name == "Jane Doe"
    assert identity.organization == "ACME"
    assert identity.organizational_units == ["eng", "sre"]
    assert identity.uid == "jdoe"


def test_common_name_over_64_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(common_name="x" * 65)


def test_empty_string_common_name_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(common_name="   ")


def test_path_length_negative_rejected():
    with pytest.raises(ValidationError):
        ClientIdentity(path_length=-1)


@pytest.mark.parametrize(
    "address,expected",
    [
        ("Jane@Example.COM", "jane@example.com"),
        ("  jdoe@example.com  ", "jdoe@example.com"),
    ],
)
def test_validate_email_normalizes(address, expected):
    assert _validate_email(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        "",
        "no-at-sign",
        "two@@example.com",
        "a@b@example.com",
        "<jdoe@example.com>",
        "jdoé@example.com",  # non-ASCII
        ("x" * 65) + "@example.com",  # local-part > 64
        "jdoe@" + ("d" * 256) + ".com",  # domain > 255
    ],
)
def test_validate_email_rejects_invalid(address):
    with pytest.raises(ValueError):
        _validate_email(address)


def test_model_rejects_invalid_email():
    with pytest.raises(ValidationError):
        ClientIdentity(primary_email="not-an-email")

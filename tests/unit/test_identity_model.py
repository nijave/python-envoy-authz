"""Unit tests for the ClientIdentity Pydantic model and email validation."""

import pytest

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


def test_common_name_over_64_dropped():
    # The model is best-effort: an invalid attribute is dropped to None rather
    # than raising, so the rest of the identity survives.
    identity = ClientIdentity(common_name="x" * 65, organization="ACME")
    assert identity.common_name is None
    assert identity.organization == "ACME"


def test_empty_string_common_name_dropped():
    assert ClientIdentity(common_name="   ").common_name is None


def test_path_length_negative_dropped():
    assert ClientIdentity(path_length=-1).path_length is None


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
        "jdoe@",  # empty domain
        "@example.com",  # empty local-part
        ("x" * 65) + "@example.com",  # local-part > 64
        "jdoe@" + ("d" * 256) + ".com",  # domain > 255
        # total > 254 while local <= 64 and domain <= 255
        ("x" * 64) + "@" + ("d" * 186) + ".com",
    ],
)
def test_validate_email_rejects_invalid(address):
    with pytest.raises(ValueError):
        _validate_email(address)


def test_model_drops_invalid_email():
    assert ClientIdentity(primary_email="not-an-email").primary_email is None


def test_model_drops_invalid_list_items_keeps_valid():
    identity = ClientIdentity(
        organizational_units=["eng", "x" * 65, "sre"],
        additional_email_addresses=["good@example.com", "bad", "two@example.org"],
    )
    assert identity.organizational_units == ["eng", "sre"]
    assert identity.additional_email_addresses == [
        "good@example.com",
        "two@example.org",
    ]

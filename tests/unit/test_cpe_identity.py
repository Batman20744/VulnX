
from vulnx.intelligence.cpe_identity import (
    parse_cpe_identity,
    normalize_product_name,
    cpe_matches_asset,
)


def test_parse_cpe_identity():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    result = parse_cpe_identity(criteria)

    assert result is not None
    assert result.part == "a"
    assert result.vendor == "apache"
    assert result.product == "log4j"
    assert result.version == "2.14.1"


def test_invalid_cpe():
    result = parse_cpe_identity("invalid-cpe")

    assert result is None


def test_normalize_product_name():
    assert normalize_product_name("Apache-Log4j") == "apachelog4j"
    assert normalize_product_name("Log4j 2") == "log4j2"


def test_matching_vendor_and_product():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    result = cpe_matches_asset(
        criteria,
        vendor="Apache",
        software_name="Log4j",
    )

    assert result is True


def test_non_matching_vendor():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    result = cpe_matches_asset(
        criteria,
        vendor="Microsoft",
        software_name="Log4j",
    )

    assert result is False


def test_non_matching_product():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    result = cpe_matches_asset(
        criteria,
        vendor="Apache",
        software_name="Tomcat",
    )

    assert result is False


def test_missing_asset_identity():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    result = cpe_matches_asset(
        criteria,
        vendor="",
        software_name="Log4j",
    )

    assert result is None

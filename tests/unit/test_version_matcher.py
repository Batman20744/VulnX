
import pytest

from vulnx.intelligence.version_matcher import (
    extract_cpe_version,
    is_version_affected,
)


def test_extract_cpe_version():
    criteria = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    assert extract_cpe_version(criteria) == "2.14.1"


def test_inclusive_version_range():
    match = {
        "vulnerable": True,
        "version_start_including": "2.0",
        "version_end_including": "2.15.0",
    }

    assert is_version_affected("2.0", match) is True
    assert is_version_affected("2.14.1", match) is True
    assert is_version_affected("2.15.0", match) is True
    assert is_version_affected("2.16.0", match) is False


def test_exclusive_version_range():
    match = {
        "vulnerable": True,
        "version_start_excluding": "2.0",
        "version_end_excluding": "2.15.0",
    }

    assert is_version_affected("2.0", match) is False
    assert is_version_affected("2.1", match) is True
    assert is_version_affected("2.14.1", match) is True
    assert is_version_affected("2.15.0", match) is False


def test_exact_cpe_version():
    match = {
        "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        "vulnerable": True,
    }

    assert is_version_affected("2.14.1", match) is True
    assert is_version_affected("2.16.0", match) is False


def test_non_vulnerable_match():
    match = {
        "vulnerable": False,
        "version_start_including": "1.0",
        "version_end_including": "3.0",
    }

    assert is_version_affected("2.0", match) is False


def test_invalid_installed_version():
    match = {
        "vulnerable": True,
        "version_start_including": "2.0",
        "version_end_including": "3.0",
    }

    assert is_version_affected("unknown-version", match) is None


def test_unknown_version_range():
    match = {
        "vulnerable": True,
    }

    assert is_version_affected("2.14.1", match) is None


def test_invalid_cpe():
    assert extract_cpe_version("invalid-cpe") is None

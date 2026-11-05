
import pytest

from vulnx.matching.vulnerability_matcher import match_asset_to_cpe


def make_log4j_range(start, end):
    return {
        "criteria": (
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
        ),
        "vulnerable": True,
        "version_start_including": start,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": end,
    }


@pytest.mark.parametrize(
    "version, start, end, expected",
    [
        ("2.0.1", "2.0.1", "2.3.1", "affected"),
        ("2.2.0", "2.0.1", "2.3.1", "affected"),
        ("2.3.0", "2.0.1", "2.3.1", "affected"),
        ("2.3.1", "2.0.1", "2.3.1", "not_affected"),
        ("2.4.0", "2.4.0", "2.12.2", "affected"),
        ("2.12.1", "2.4.0", "2.12.2", "affected"),
        ("2.12.2", "2.4.0", "2.12.2", "not_affected"),
        ("2.13.0", "2.13.0", "2.15.0", "affected"),
        ("2.14.1", "2.13.0", "2.15.0", "affected"),
        ("2.15.0", "2.13.0", "2.15.0", "not_affected"),
    ],
)
def test_log4j_version_boundaries(
    version,
    start,
    end,
    expected,
):
    cpe = make_log4j_range(start, end)

    result = match_asset_to_cpe(
        vendor="Apache",
        software_name="Log4j",
        software_version=version,
        cpe_match=cpe,
    )

    assert result["status"] == expected

@pytest.mark.parametrize(
    "version",
    [
        "2.0",
        "2.0-beta9",
        "2.0-rc1",
        "2.0-rc2",
    ],
)
def test_log4j_explicit_cpe_versions(version):
    cpe = {
        "criteria": (
            f"cpe:2.3:a:apache:log4j:{version}:*:*:*:*:*:*:*"
        ),
        "vulnerable": True,
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
    }

    result = match_asset_to_cpe(
        vendor="Apache",
        software_name="Log4j",
        software_version=version,
        cpe_match=cpe,
    )

    assert result["status"] == "affected"

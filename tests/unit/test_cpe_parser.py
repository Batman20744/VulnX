
import pytest

from vulnx.intelligence.cpe_parser import (
    parse_cpe_match,
    parse_configuration_node,
    parse_cve_configurations,
)


def test_parse_cpe_match():
    match = {
        "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        "vulnerable": True,
        "matchCriteriaId": "test-123",
        "versionStartIncluding": "2.0",
        "versionEndExcluding": "2.15.0",
    }

    result = parse_cpe_match(match)

    assert result["vulnerable"] is True
    assert result["version_start_including"] == "2.0"
    assert result["version_end_excluding"] == "2.15.0"
    assert result["match_criteria_id"] == "test-123"


def test_parse_configuration_node():
    node = {
        "operator": "AND",
        "negate": False,
        "cpeMatch": [
            {
                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "vulnerable": True,
            }
        ],
        "children": [
            {
                "operator": "OR",
                "negate": True,
                "cpeMatch": [],
                "children": [],
            }
        ],
    }

    result = parse_configuration_node(node)

    assert result["operator"] == "AND"
    assert result["negate"] is False
    assert len(result["matches"]) == 1
    assert len(result["children"]) == 1
    assert result["children"][0]["negate"] is True


def test_parse_cve_configurations():
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                                            "vulnerable": True,
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }

    result = parse_cve_configurations(response)

    assert len(result) == 1
    assert result[0]["operator"] == "OR"
    assert len(result[0]["matches"]) == 1


def test_empty_vulnerabilities():
    result = parse_cve_configurations(
        {"vulnerabilities": []}
    )

    assert result == []


def test_missing_configurations():
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228"
                }
            }
        ]
    }

    result = parse_cve_configurations(response)

    assert result == []

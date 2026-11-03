
import pytest

from vulnx.intelligence.normalizer import normalize_cve


@pytest.fixture
def sample_nvd_response():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apache Log4j2 remote code execution vulnerability."
                        }
                    ],
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2026-08-11T19:33:44.513",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L"
                                }
                            }
                        ]
                    },
                    "references": [
                        {
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                        }
                    ]
                }
            }
        ]
    }


def test_normalize_cve_id(sample_nvd_response):
    result = normalize_cve(sample_nvd_response)

    assert result["cve_id"] == "CVE-2021-44228"


def test_normalize_cvss_score(sample_nvd_response):
    result = normalize_cve(sample_nvd_response)

    assert result["cvss_score"] == 10.0
    assert result["severity"] == "CRITICAL"
    assert result["cvss_version"] == "3.1"


def test_normalize_description(sample_nvd_response):
    result = normalize_cve(sample_nvd_response)

    assert "Log4j2" in result["description"]


def test_normalize_references(sample_nvd_response):
    result = normalize_cve(sample_nvd_response)

    assert len(result["references"]) == 1
    assert "CVE-2021-44228" in result["references"][0]


def test_missing_cvss_data(sample_nvd_response):
    sample_nvd_response["vulnerabilities"][0]["cve"]["metrics"] = {}

    result = normalize_cve(sample_nvd_response)

    assert result["cvss_score"] is None
    assert result["severity"] == "UNKNOWN"


def test_missing_vulnerability_data():
    with pytest.raises(ValueError):
        normalize_cve({"vulnerabilities": []})


from typing import Any


def _get_english_description(descriptions: list) -> str | None:
    """Extract the English CVE description."""

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value")

    return None


def _get_cvss_data(metrics: dict) -> dict:
    """Extract the best available CVSS metric."""

    metric_versions = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for version in metric_versions:
        entries = metrics.get(version, [])

        if not entries:
            continue

        metric = entries[0]
        cvss = metric.get("cvssData", {})

        return {
            "cvss_version": cvss.get("version"),
            "cvss_score": cvss.get("baseScore"),
            "severity": (
                cvss.get("baseSeverity")
                or metric.get("baseSeverity")
                or "UNKNOWN"
            ),
            "vector": cvss.get("vectorString"),
        }

    return {
        "cvss_version": None,
        "cvss_score": None,
        "severity": "UNKNOWN",
        "vector": None,
    }


def normalize_cve(raw_response: dict[str, Any]) -> dict:
    """Convert an NVD response into a VulnX record."""

    vulnerabilities = raw_response.get("vulnerabilities", [])

    if not vulnerabilities:
        raise ValueError("No vulnerability data found.")

    cve = vulnerabilities[0].get("cve", {})

    if not cve.get("id"):
        raise ValueError("CVE ID is missing.")

    cvss_data = _get_cvss_data(cve.get("metrics", {}))

    references = [
        item["url"]
        for item in cve.get("references", [])
        if item.get("url")
    ]

    return {
        "cve_id": cve["id"],
        "description": _get_english_description(
            cve.get("descriptions", [])
        ),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_version": cvss_data["cvss_version"],
        "cvss_score": cvss_data["cvss_score"],
        "severity": cvss_data["severity"],
        "cvss_vector": cvss_data["vector"],
        "references": references,
        "source": "NVD",
    }

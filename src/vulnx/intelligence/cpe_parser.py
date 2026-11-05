
from typing import Any


def parse_cpe_match(cpe_match: dict[str, Any]) -> dict:
    """
    Extract product identity and version boundaries
    from an NVD CPE match entry.
    """

    return {
        "criteria": cpe_match.get("criteria"),
        "vulnerable": cpe_match.get("vulnerable", False),
        "match_criteria_id": cpe_match.get("matchCriteriaId"),
        "version_start_including": cpe_match.get(
            "versionStartIncluding"
        ),
        "version_start_excluding": cpe_match.get(
            "versionStartExcluding"
        ),
        "version_end_including": cpe_match.get(
            "versionEndIncluding"
        ),
        "version_end_excluding": cpe_match.get(
            "versionEndExcluding"
        ),
    }


def parse_configuration_node(node: dict[str, Any]) -> dict:
    """
    Recursively parse NVD configuration nodes.

    Preserves AND/OR operators and negation.
    """

    result = {
        "operator": node.get("operator", "OR"),
        "negate": node.get("negate", False),
        "matches": [],
        "children": [],
    }

    for match in node.get("cpeMatch", []):
        result["matches"].append(parse_cpe_match(match))

    for child in node.get("children", []):
        result["children"].append(
            parse_configuration_node(child)
        )

    return result


def parse_cve_configurations(
    raw_response: dict[str, Any]
) -> list[dict]:
    """
    Extract configuration trees from an NVD CVE response.
    """

    vulnerabilities = raw_response.get("vulnerabilities", [])

    if not vulnerabilities:
        return []

    cve = vulnerabilities[0].get("cve", {})
    configurations = cve.get("configurations", [])

    parsed_configurations = []

    for configuration in configurations:
        nodes = configuration.get("nodes", [])

        for node in nodes:
            parsed_configurations.append(
                parse_configuration_node(node)
            )

    return parsed_configurations

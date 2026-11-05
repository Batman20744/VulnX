
from vulnx.matching.vulnerability_matcher import match_asset_to_cpe


def evaluate_configuration_node(
    node: dict,
    vendor: str | None,
    software_name: str,
    software_version: str,
) -> bool | None:
    """
    Evaluate one NVD configuration node.

    True  = configuration matches
    False = configuration does not match
    None  = insufficient information
    """

    operator = node.get("operator", "OR").upper()
    negate = node.get("negate", False)

    results = []

    # Evaluate CPE matches in this node.
    for cpe_match in node.get("matches", []):
        result = match_asset_to_cpe(
            vendor=vendor,
            software_name=software_name,
            software_version=software_version,
            cpe_match=cpe_match,
        )

        status = result["status"]

        if status == "affected":
            results.append(True)
        elif status == "not_affected":
            results.append(False)
        else:
            results.append(None)

    # Evaluate nested child nodes recursively.
    for child in node.get("children", []):
        results.append(
            evaluate_configuration_node(
                child,
                vendor,
                software_name,
                software_version,
            )
        )

    if not results:
        return None

    if operator == "AND":
        if False in results:
            value = False
        elif all(result is True for result in results):
            value = True
        else:
            value = None

    elif operator == "OR":
        if True in results:
            value = True
        elif all(result is False for result in results):
            value = False
        else:
            value = None

    else:
        return None

    if negate and value is not None:
        return not value

    return value


def evaluate_cve_configurations(
    configurations: list[dict],
    vendor: str | None,
    software_name: str,
    software_version: str,
) -> bool | None:
    """
    Evaluate all top-level NVD configurations.

    NVD configuration alternatives are treated as OR.
    """

    if not configurations:
        return None

    results = [
        evaluate_configuration_node(
            configuration,
            vendor,
            software_name,
            software_version,
        )
        for configuration in configurations
    ]

    if True in results:
        return True

    if all(result is False for result in results):
        return False

    return None

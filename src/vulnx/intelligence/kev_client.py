
import httpx


KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_kev_catalog() -> set[str]:
    """
    Download the official CISA KEV catalog.

    Returns:
        A set of CVE IDs confirmed in the KEV catalog.
    """

    with httpx.Client(timeout=30.0) as client:
        response = client.get(KEV_CATALOG_URL)
        response.raise_for_status()

        payload = response.json()

    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise ValueError("Invalid CISA KEV catalog format.")

    kev_ids = set()

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue

        cve_id = item.get("cveID")

        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            kev_ids.add(cve_id.upper())

    return kev_ids

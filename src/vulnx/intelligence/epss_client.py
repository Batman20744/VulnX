
import httpx


EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch current EPSS scores from FIRST.

    Returns:
        Dictionary mapping CVE IDs to EPSS scores.
        Example: {"CVE-2021-44228": 0.99}
    """

    unique_ids = sorted({
        cve.strip().upper()
        for cve in cve_ids
        if isinstance(cve, str) and cve.strip()
    })

    if not unique_ids:
        return {}

    scores = {}

    # Query in batches to keep request URLs manageable.
    with httpx.Client(timeout=15.0) as client:
        for start in range(0, len(unique_ids), 100):
            batch = unique_ids[start:start + 100]

            response = client.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
            )

            response.raise_for_status()

            payload = response.json()

            if payload.get("status") != "OK":
                raise ValueError("FIRST EPSS API returned an unsuccessful status.")

            for item in payload.get("data", []):
                cve_id = item.get("cve")
                epss_value = item.get("epss")

                if not cve_id or epss_value is None:
                    continue

                try:
                    score = float(epss_value)
                except (TypeError, ValueError):
                    continue

                if 0.0 <= score <= 1.0:
                    scores[cve_id.upper()] = score

    return scores

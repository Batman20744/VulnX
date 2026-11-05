
def calculate_risk_score(
    cvss_score: float | None,
    epss_score: float | None,
    is_kev: bool,
) -> int:
    """
    Calculate a VulnX prioritization score from 0 to 100.

    CVSS: 0-50 points
    EPSS: 0-30 points
    KEV:  0-20 points

    Missing data contributes zero points.
    """

    score = 0.0

    # CVSS contribution: maximum 50 points.
    if cvss_score is not None:
        cvss = max(0.0, min(float(cvss_score), 10.0))
        score += (cvss / 10.0) * 50

    # EPSS contribution: maximum 30 points.
    if epss_score is not None:
        epss = max(0.0, min(float(epss_score), 1.0))
        score += epss * 30

    # Known exploitation in the wild.
    if is_kev:
        score += 20

    return round(min(score, 100))


def classify_risk(score: int) -> str:
    """Convert a VulnX score into a priority classification."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


import pytest

from vulnx.services.risk_scoring import (
    calculate_risk_score,
    classify_risk,
)


@pytest.mark.parametrize(
    "cvss, epss, kev, expected",
    [
        (10.0, 1.0, True, 100),
        (10.0, 0.0, False, 50),
        (0.0, 1.0, True, 50),
        (None, None, False, 0),
        (8.0, 0.5, True, 75),
        (5.0, 0.5, False, 40),
    ],
)
def test_calculate_risk_score(
    cvss, epss, kev, expected
):
    assert calculate_risk_score(cvss, epss, kev) == expected


@pytest.mark.parametrize(
    "score, expected",
    [
        (100, "CRITICAL"),
        (80, "CRITICAL"),
        (79, "HIGH"),
        (60, "HIGH"),
        (59, "MEDIUM"),
        (30, "MEDIUM"),
        (29, "LOW"),
        (0, "LOW"),
    ],
)
def test_classify_risk(score, expected):
    assert classify_risk(score) == expected

def test_critical_vulnerability_with_high_epss_and_kev():
    score = calculate_risk_score(
        cvss_score=10.0,
        epss_score=0.99999,
        is_kev=True,
    )

    assert score == 100
    assert classify_risk(score) == "CRITICAL"


def test_high_cvss_without_exploitation_evidence():
    score = calculate_risk_score(
        cvss_score=9.0,
        epss_score=0.0,
        is_kev=False,
    )

    assert score == 45
    assert classify_risk(score) == "MEDIUM"


def test_kev_increases_risk_score():
    without_kev = calculate_risk_score(
        cvss_score=7.0,
        epss_score=0.5,
        is_kev=False,
    )

    with_kev = calculate_risk_score(
        cvss_score=7.0,
        epss_score=0.5,
        is_kev=True,
    )

    assert with_kev > without_kev
    assert with_kev - without_kev == 20


def test_missing_intelligence_data():
    score = calculate_risk_score(
        cvss_score=None,
        epss_score=None,
        is_kev=False,
    )

    assert score == 0
    assert classify_risk(score) == "LOW"


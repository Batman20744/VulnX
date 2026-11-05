
from types import SimpleNamespace

from vulnx.api.findings import (
    get_risk_summary,
    get_risk_sorted_findings,
)


def make_finding(finding_id, cvss, epss, kev):
    return SimpleNamespace(
        id=finding_id,
        cvss_score=cvss,
        epss_score=epss,
        is_kev=kev,
    )


class FakeQuery:
    def __init__(self, records):
        self.records = records

    def all(self):
        return self.records


class FakeDB:
    def __init__(self, records):
        self.records = records

    def query(self, model):
        return FakeQuery(self.records)


def test_risk_summary_counts_findings():
    findings = [
        make_finding(1, 10.0, 1.0, True),
        make_finding(2, 9.0, 0.0, False),
        make_finding(3, 5.0, 0.5, False),
        make_finding(4, None, None, False),
    ]

    result = get_risk_summary(FakeDB(findings))

    assert result["total_findings"] == 4
    assert result["critical"] == 1
    assert result["high"] == 0
    assert result["medium"] == 2
    assert result["low"] == 1
    assert result["kev_findings"] == 1
    assert result["average_risk_score"] == 46.25


def test_risk_summary_with_no_findings():
    result = get_risk_summary(FakeDB([]))

    assert result["total_findings"] == 0
    assert result["critical"] == 0
    assert result["high"] == 0
    assert result["medium"] == 0
    assert result["low"] == 0
    assert result["kev_findings"] == 0
    assert result["average_risk_score"] == 0


def test_findings_sorted_by_risk():
    findings = [
        make_finding(1, 2.0, 0.0, False),
        make_finding(2, 10.0, 1.0, True),
        make_finding(3, 7.0, 0.5, False),
    ]

    result = get_risk_sorted_findings(findings)

    assert [finding.id for finding in result] == [2, 3, 1]

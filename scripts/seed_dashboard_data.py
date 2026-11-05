
from datetime import datetime, timedelta, timezone

from vulnx.core.database import SessionLocal
from vulnx.models.asset import SoftwareAsset
from vulnx.models.scan import ScanRecord
from vulnx.models.finding import VulnerabilityFinding


PREFIX = "VulnX-Demo"

ASSETS = [
    ("Demo-Web-Server", "Apache HTTP Server", "2.4.49", "Apache", "Ubuntu 22.04"),
    ("Demo-Database", "MySQL", "5.7.35", "Oracle", "Ubuntu 22.04"),
    ("Demo-Application", "Log4j", "2.14.1", "Apache", "Ubuntu 22.04"),
    ("Demo-Workstation", "OpenSSH", "8.2", "OpenBSD", "Ubuntu 20.04"),
    ("Demo-Container", "Docker Engine", "20.10.5", "Docker", "Debian 12"),
    ("Demo-Web-Proxy", "Nginx", "1.18.0", "F5", "Ubuntu 22.04"),
    ("Demo-Python-Service", "Python", "3.8.10", "Python", "Ubuntu 20.04"),
    ("Demo-Java-Service", "Apache Tomcat", "9.0.30", "Apache", "Debian 11"),
    ("Demo-Kernel", "Linux Kernel", "5.4.0", "Linux", "Ubuntu 20.04"),
    ("Demo-Endpoint", "OpenSSL", "1.1.1", "OpenSSL", "Debian 11"),
]

# CVE IDs are deliberately synthetic and must not be treated as real CVEs.
FINDINGS = [
    (0, "CVE-2099-0002", "Demo: Web server remote code execution", "CRITICAL", 9.8, 0.92, True),
    (0, "CVE-2099-0003", "Demo: HTTP request smuggling", "HIGH", 8.1, 0.72, False),
    (0, "CVE-2099-0004", "Demo: Information disclosure", "MEDIUM", 5.3, 0.34, False),
    (1, "CVE-2099-0005", "Demo: Database authentication bypass", "CRITICAL", 9.6, 0.88, True),
    (1, "CVE-2099-0006", "Demo: SQL privilege escalation", "HIGH", 7.8, 0.63, False),
    (1, "CVE-2099-0007", "Demo: Weak database configuration", "LOW", 3.1, 0.08, False),
    (2, "CVE-2099-0008", "Demo: Java logging remote code execution", "CRITICAL", 10.0, 0.98, True),
    (2, "CVE-2099-0009", "Demo: Unsafe deserialization", "HIGH", 8.6, 0.76, False),
    (2, "CVE-2099-0010", "Demo: Logging information exposure", "MEDIUM", 5.5, 0.29, False),
    (3, "CVE-2099-0011", "Demo: SSH authentication weakness", "HIGH", 7.5, 0.58, False),
    (3, "CVE-2099-0012", "Demo: Weak cryptographic settings", "MEDIUM", 5.0, 0.21, False),
    (4, "CVE-2099-0013", "Demo: Container privilege escalation", "CRITICAL", 9.4, 0.91, True),
    (4, "CVE-2099-0014", "Demo: Container information leak", "MEDIUM", 6.0, 0.40, False),
    (5, "CVE-2099-0015", "Demo: Reverse proxy request issue", "HIGH", 8.0, 0.69, False),
    (5, "CVE-2099-0016", "Demo: TLS configuration weakness", "LOW", 3.7, 0.12, False),
    (6, "CVE-2099-0017", "Demo: Python package code execution", "CRITICAL", 9.1, 0.86, True),
    (6, "CVE-2099-0018", "Demo: Dependency vulnerability", "MEDIUM", 6.2, 0.31, False),
    (7, "CVE-2099-0019", "Demo: Tomcat remote code execution", "HIGH", 8.8, 0.81, True),
    (7, "CVE-2099-0020", "Demo: Application information leak", "LOW", 2.9, 0.06, False),
    (8, "CVE-2099-0021", "Demo: Kernel privilege escalation", "CRITICAL", 9.7, 0.95, True),
    (8, "CVE-2099-0022", "Demo: Kernel denial of service", "MEDIUM", 5.8, 0.25, False),
    (9, "CVE-2099-0023", "Demo: OpenSSL memory disclosure", "HIGH", 7.9, 0.66, False),
    (9, "CVE-2099-0024", "Demo: Weak certificate validation", "LOW", 3.5, 0.10, False),
]

def main():
    db = SessionLocal()

    try:
        now = datetime.now(timezone.utc)

        # 1. Create demo assets only when they do not already exist.
        assets_by_name = {}

        for name, software, version, vendor, os_name in ASSETS:
            asset_name = f"{PREFIX}-{name}"

            asset = (
                db.query(SoftwareAsset)
                .filter(SoftwareAsset.asset_name == asset_name)
                .first()
            )

            if asset is None:
                asset = SoftwareAsset(
                    asset_name=asset_name,
                    software_name=software,
                    software_version=version,
                    vendor=vendor,
                    operating_system=os_name,
                    asset_type="software",
                    description="Synthetic VulnX dashboard demonstration asset."
                )
                db.add(asset)
                db.flush()

            assets_by_name[name] = asset

        # 2. Create demo scans with historical dates.
        scans = []

        for day in [60, 50, 40, 30, 20, 12, 6, 1]:
            scan_name = f"{PREFIX}-Scan-{day}d"

            scan = (
                db.query(ScanRecord)
                .filter(ScanRecord.scan_name == scan_name)
                .first()
            )

            if scan is None:
                started = now - timedelta(days=day)

                scan = ScanRecord(
                    scan_name=scan_name,
                    scan_type="demo",
                    target="VulnX synthetic dashboard dataset",
                    status="completed",
                    total_assets=0,
                    total_findings=0,
                    started_at=started,
                    completed_at=started + timedelta(minutes=5),
                    summary="Synthetic demonstration scan; not a real security assessment."
                )
                db.add(scan)
                db.flush()

            scans.append(scan)

        # 3. Distribute findings across scans and assets.
        created_findings = 0

        for index, item in enumerate(FINDINGS):
            asset_index, cve_id, title, severity, cvss, epss, kev = item

            asset = assets_by_name[ASSETS[asset_index][0]]
            scan = scans[index % len(scans)]

            existing = (
                db.query(VulnerabilityFinding)
                .filter(
                    VulnerabilityFinding.scan_id == scan.id,
                    VulnerabilityFinding.asset_id == asset.id,
                    VulnerabilityFinding.cve_id == cve_id
                )
                .first()
            )

            if existing is not None:
                continue

            detected = scan.started_at + timedelta(minutes=index)

            finding = VulnerabilityFinding(
                asset_id=asset.id,
                scan_id=scan.id,
                cve_id=cve_id,
                title=title,
                description=(
                    "Synthetic demonstration finding created to populate "
                    "VulnX dashboard charts. This is not a real CVE record."
                ),
                severity=severity,
                cvss_score=cvss,
                epss_score=epss,
                is_kev=kev,
                remediation="Apply the appropriate vendor security update and verify the configuration.",
                status="open",
                detected_at=detected
            )

            db.add(finding)
            created_findings += 1

        db.flush()

        # 4. Update only the demo scans' summary counts.
        for scan in scans:
            scan.total_assets = (
                db.query(SoftwareAsset)
                .filter(SoftwareAsset.asset_name.like(f"{PREFIX}-%"))
                .count()
            )

            scan.total_findings = (
                db.query(VulnerabilityFinding)
                .filter(VulnerabilityFinding.scan_id == scan.id)
                .count()
            )

        db.commit()

        print("\nVulnX dashboard dataset completed.")
        print(f"Demo assets: {len(assets_by_name)}")
        print(f"Demo scans: {len(scans)}")
        print(f"New findings added: {created_findings}")
        print("Existing records were preserved.")
        print("Synthetic CVEs use the CVE-2099 prefix.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()


import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from vulnx.intelligence.nvd_client import NVDClient
from vulnx.intelligence.normalizer import normalize_cve
from vulnx.models.cve_intelligence import CVEIntelligence


async def fetch_and_store_cve(
    cve_id: str,
    db: Session,
) -> CVEIntelligence:
    """Fetch a CVE from NVD and save or update it."""

    client = NVDClient()
    raw_response = await client.get_cve(cve_id)
    data = normalize_cve(raw_response)

    record = (
        db.query(CVEIntelligence)
        .filter(CVEIntelligence.cve_id == data["cve_id"])
        .first()
    )

    if record is None:
        record = CVEIntelligence(cve_id=data["cve_id"])
        db.add(record)

    record.description = data["description"]
    record.severity = data["severity"]
    record.cvss_score = data["cvss_score"]
    record.cvss_version = data["cvss_version"]
    record.published = data["published"]
    record.last_modified = data["last_modified"]
    record.references = json.dumps(data["references"])
    record.source = data["source"]
    record.retrieved_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()
        raise

    return record

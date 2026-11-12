from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from io import BytesIO

from vulnx.core.database import get_db
from vulnx.services.report_service import (
    generate_security_pdf,
    generate_vulnerability_csv,
)


router = APIRouter(
    prefix="/reports",
    tags=["Security Reports"],
)


@router.get("/pdf")
def download_security_pdf(
    db: Session = Depends(get_db),
):
    pdf_bytes = generate_security_pdf(db)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                'attachment; filename="VulnX_Security_Report.pdf"'
        },
    )


@router.get("/csv")
def download_vulnerability_csv(
    db: Session = Depends(get_db),
):
    csv_bytes = generate_vulnerability_csv(db)

    return StreamingResponse(
        BytesIO(csv_bytes),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="VulnX_Vulnerability_Report.csv"'
        },
    )
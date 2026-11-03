
import httpx

from vulnx.core.config import settings


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClientError(Exception):
    """Raised when an NVD API request fails."""


class NVDClient:
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    async def get_cve(self, cve_id: str) -> dict:
        """Retrieve a CVE record from the NVD API."""

        cve_id = cve_id.strip().upper()

        if not cve_id.startswith("CVE-"):
            raise ValueError("Invalid CVE ID format.")

        headers = {}

        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                headers=headers,
            ) as client:

                response = await client.get(
                    NVD_API_URL,
                    params={"cveId": cve_id},
                )

                response.raise_for_status()
                data = response.json()

                if not data.get("vulnerabilities"):
                    raise NVDClientError(
                        f"No NVD record found for {cve_id}"
                    )

                return data

        except httpx.TimeoutException as exc:
            raise NVDClientError(
                "NVD API request timed out."
            ) from exc

        except httpx.HTTPStatusError as exc:
            raise NVDClientError(
                f"NVD API returned HTTP {exc.response.status_code}."
            ) from exc

        except httpx.RequestError as exc:
            raise NVDClientError(
                "Could not connect to the NVD API."
            ) from exc

        except ValueError as exc:
            raise NVDClientError(
                "NVD returned an invalid JSON response."
            ) from exc

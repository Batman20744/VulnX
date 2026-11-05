
from packaging.version import InvalidVersion, Version


def extract_cpe_version(criteria: str | None) -> str | None:
    if not criteria:
        return None

    parts = criteria.split(":")

    if len(parts) != 13 or parts[0:2] != ["cpe", "2.3"]:
        return None

    version = parts[5]

    if version in {"*", "-"}:
        return None

    return version


def is_version_affected(
    installed_version: str,
    cpe_match: dict,
) -> bool | None:

    if not cpe_match.get("vulnerable", False):
        return False

    try:
        installed = Version(installed_version.strip())
    except (InvalidVersion, AttributeError):
        return None

    start_including = cpe_match.get("version_start_including")
    start_excluding = cpe_match.get("version_start_excluding")
    end_including = cpe_match.get("version_end_including")
    end_excluding = cpe_match.get("version_end_excluding")

    try:
        boundaries = (
            start_including,
            start_excluding,
            end_including,
            end_excluding,
        )

        has_range = any(
            boundary is not None
            for boundary in boundaries
        )

        if has_range:

            if start_including is not None:
                if installed < Version(start_including):
                    return False

            if start_excluding is not None:
                if installed <= Version(start_excluding):
                    return False

            if end_including is not None:
                if installed > Version(end_including):
                    return False

            if end_excluding is not None:
                if installed >= Version(end_excluding):
                    return False

            return True

        criteria_version = extract_cpe_version(
            cpe_match.get("criteria")
        )

        # Wildcard CPE without version boundaries:
        # insufficient evidence for a positive match.
        if criteria_version is None:
            return None

        return installed == Version(criteria_version)

    except (InvalidVersion, TypeError, AttributeError):
        return None

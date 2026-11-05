
from dataclasses import dataclass


@dataclass(frozen=True)
class CPEIdentity:
    part: str
    vendor: str
    product: str
    version: str


def parse_cpe_identity(criteria: str) -> CPEIdentity | None:
    """
    Parse a CPE 2.3 identifier.

    Format:
    cpe:2.3:part:vendor:product:version:...
    """

    if not isinstance(criteria, str):
        return None

    parts = criteria.split(":")

    if len(parts) != 13:
        return None

    if parts[0] != "cpe" or parts[1] != "2.3":
        return None

    part, vendor, product, version = parts[2:6]

    if part not in {"a", "o", "h"}:
        return None

    if not vendor or not product:
        return None

    return CPEIdentity(
        part=part,
        vendor=vendor,
        product=product,
        version=version,
    )


def normalize_product_name(value: str | None) -> str:
    """Normalize product names for preliminary comparison."""

    if not value:
        return ""

    return "".join(
        character.lower()
        for character in value
        if character.isalnum()
    )


def cpe_matches_asset(
    criteria: str,
    vendor: str,
    software_name: str,
) -> bool | None:
    """
    Compare CPE vendor and product with an inventory asset.

    Returns None when the CPE cannot be parsed.
    """

    identity = parse_cpe_identity(criteria)

    if identity is None:
        return None

    cpe_vendor = normalize_product_name(identity.vendor)
    cpe_product = normalize_product_name(identity.product)

    asset_vendor = normalize_product_name(vendor)
    asset_product = normalize_product_name(software_name)

    if not asset_vendor or not asset_product:
        return None

    return (
        cpe_vendor == asset_vendor
        and cpe_product == asset_product
    )

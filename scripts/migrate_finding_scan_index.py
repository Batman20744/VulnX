
from sqlalchemy import inspect

from vulnx.core.database import engine


OLD_INDEX = "ix_finding_cve_asset"
NEW_INDEX = "ix_finding_scan_asset_cve"


def migrate():
    inspector = inspect(engine)

    if "vulnerability_findings" not in inspector.get_table_names():
        raise RuntimeError(
            "vulnerability_findings table does not exist."
        )

    indexes = {
        index["name"]
        for index in inspector.get_indexes(
            "vulnerability_findings"
        )
    }

    with engine.begin() as connection:

        if OLD_INDEX in indexes:
            connection.exec_driver_sql(
                f'DROP INDEX "{OLD_INDEX}"'
            )
            print("Old unique index removed.")

        if NEW_INDEX not in indexes:
            connection.exec_driver_sql(
                f"""
                CREATE UNIQUE INDEX "{NEW_INDEX}"
                ON vulnerability_findings (
                    scan_id,
                    asset_id,
                    cve_id
                )
                """
            )
            print("New scan-history index created.")

        else:
            print("New index already exists.")

    print("Finding index migration completed.")


if __name__ == "__main__":
    migrate()

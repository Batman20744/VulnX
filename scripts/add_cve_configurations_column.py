
from sqlalchemy import inspect, text

from vulnx.core.database import engine


def migrate():
    inspector = inspect(engine)

    if "cve_intelligence" not in inspector.get_table_names():
        raise RuntimeError(
            "cve_intelligence table does not exist. "
            "Start VulnX once to initialize the database."
        )

    columns = {
        column["name"]
        for column in inspector.get_columns("cve_intelligence")
    }

    if "configurations" in columns:
        print("Migration skipped: configurations column already exists.")
        return

    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE cve_intelligence "
                "ADD COLUMN configurations TEXT"
            )
        )

    print("Migration successful: configurations column added.")


if __name__ == "__main__":
    migrate()

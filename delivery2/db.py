import json
from typing import Dict, Any

DB_FILE = "db.json"
db_cache: Dict[str, Any] = {}


def load_db() -> Dict[str, Any]:
    """Load the database from the file, or initialize an empty one if the file doesn't exist."""
    global db_cache

    if not db_cache:
        try:
            with open(DB_FILE, "r") as file:
                db_cache = json.load(file)
        except FileNotFoundError:
            db_cache = {}

    return db_cache


def save_db() -> None:
    """Save the current in-memory database to the file."""
    with open(DB_FILE, "w") as file:
        json.dump(db_cache, file, indent=4)


def initialize_db() -> None:
    """Initialize an empty database structure."""
    global db_cache
    db_cache = {
        "organizations": {},
        "subjects": {},
        "sessions": {}
    }


def clear_db() -> None:
    """Clear the in-memory database and save the empty structure."""
    initialize_db()
    save_db()


if __name__ == "__main__":
    initialize_db()
    save_db()

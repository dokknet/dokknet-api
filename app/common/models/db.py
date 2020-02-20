import threading
from typing import cast

from app.common.config import config
from app.common.db import Database


_local = threading.local()


def get_db() -> Database:
    """Get thread-local database object.

    Returns:
        The database object.

    """
    if not hasattr(_local, 'db'):
        _local.db = Database(config.main_table)
    return cast(Database, _local.db)

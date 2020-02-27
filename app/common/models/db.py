import threading
from typing import cast

from dokklib_db import Table

from app.common.config import config


_local = threading.local()


def get_table() -> Table:
    """Get thread-local table object.

    Returns:
        The table object.

    """
    if not hasattr(_local, 'db'):
        _local.db = Table(config.main_table)
    return cast(Table, _local.db)

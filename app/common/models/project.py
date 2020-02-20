"""Documentation project model."""
from typing import Optional, TypedDict, cast

import app.common.db as db
import app.common.models.entities as ent
from app.common.models.db import get_db


class ProjectAttributes(TypedDict):
    """Project attributes."""

    TrialDays: int


def fetch(project_domain: str) -> Optional[ProjectAttributes]:
    """Fetch project attributes based on domain name.

    Args:
        project_domain: The project's domain name.

    Returns:
        The project attributes if the project exists.

    """
    pk = db.PartitionKey(ent.Project, project_domain)
    sk = db.SortKey(ent.Project, project_domain)
    res = get_db().get_item(pk, sk, attributes=['TrialDays'])
    if res is not None:
        return cast(ProjectAttributes, res)
    else:
        return None


def exists(project_domain: str) -> bool:
    """Check whether a project exists in the database.

    Args:
        project_domain: The project's domain name.

    Returns:
        True if the project exists.

    """
    pk = db.PartitionKey(ent.Project, project_domain)
    sk = db.SortKey(ent.Project, project_domain)
    res = get_db().get_item(pk, sk)
    return bool(res)

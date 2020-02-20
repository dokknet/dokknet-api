"""User group subscription model."""
from typing import Optional, TypedDict, cast

import app.common.db as db
import app.common.models.entities as ent
from app.common.models.db import get_db
from app.common.models.user_sub import get_trial_end_date


class GroupSubAttributes(TypedDict):
    """Group subscription attributes."""

    IsActive: bool


def _get_group_create_op(group_name: str, project_domain: str) -> db.InsertArg:
    pk_gr = db.PartitionKey(ent.Group, group_name)
    sk_gr = db.SortKey(ent.GroupSub, project_domain)
    attr: GroupSubAttributes = {
        'IsActive': True
    }
    return db.InsertArg(pk_gr, sk_gr, attributes=attr)


def _get_trial_end_op(group_name: str, project_domain: str, trial_days: int) \
        -> db.InsertArg:
    trial_end = get_trial_end_date(trial_days)
    pk = db.PartitionKey(ent.TrialEnd, trial_end)
    # Concatenation of values ensures uniqueness of item.
    sk = db.SortKey(ent.GroupTrialEnd, f'{group_name}|{project_domain}')
    return db.InsertArg(pk, sk)


def fetch(group_name: str, project_domain: str, consistent: bool = False) \
        -> Optional[GroupSubAttributes]:
    """Fetch subscription attributes for a group.

    Args:
        group_name: The user's email address.
        project_domain: The project's domain name.
        consistent: Whether the read should be strongly consistent.


    Returns:
        The subscription attributes if the subscription exists.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    pk = db.PartitionKey(ent.Group, group_name)
    sk = db.SortKey(ent.GroupSub, project_domain)
    res = get_db().get_item(pk, sk,
                            consistent=consistent,
                            attributes=['IsActive'])
    if res is not None:
        return cast(GroupSubAttributes, res)
    else:
        return None


def create(group_name: str, project_domain: str, trial_days: int) -> None:
    """Create a group subscription.

    Args:
        group_name: The group's name that uniquely identifies it.
        project_domain: The project's domain name that uniquely identifies it.
        trial_days: The number of trial days for the project.

    Raises:
        `db.ConditionalCheckFailedError` if the subscription already exists.
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    # TODO (abiro) Stripe logic
    # TODO (abiro) Publish group sub created event to propagate to members
    group_op = _get_group_create_op(group_name=group_name,
                                    project_domain=project_domain)
    trial_end_op = _get_trial_end_op(group_name=group_name,
                                     project_domain=project_domain,
                                     trial_days=trial_days)
    get_db().transact_write_items([
        group_op,
        trial_end_op
    ])


def recreate(group_name: str, project_domain: str) -> None:
    """Recreate a subscription to a project for a group that has lapsed.

    Args:
        group_name: The group's name that uniquely identifies it.
        project_domain: The project's domain name that uniquely identifies it.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    raise NotImplementedError

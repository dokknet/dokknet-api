"""User group model."""
from typing import TypedDict

import dokklib_db as db

import app.common.models.entities as ent
from app.common.models.db import get_table


class GroupAttributes(TypedDict):
    """Group attributes."""

    # The user's email who is the owner of the group.
    OwnerEmail: str


def is_owner(group_name: str, user_email: str) -> bool:
    """Check whether a user is an owner of a group.

    Args:
        group_name: The group's name that uniquely identifies it.
        user_email: The user's email address.

    Returns:
        True if the user is the owner of the group.

    """
    pk = db.PartitionKey(ent.Group, group_name)
    sk = db.SortKey(ent.Group, group_name)
    res = get_table().get(pk, sk, attributes=['OwnerEmail'])
    return res is not None and res['OwnerEmail'] == user_email

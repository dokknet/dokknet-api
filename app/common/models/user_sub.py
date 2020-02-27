"""User subscription model."""
import datetime
from typing import List, Optional, TypedDict, cast

import boto3.dynamodb.conditions as cond

import dokklib_db as db

import app.common.models.entities as ent
from app.common.models.db import get_table


class SubAttributes(TypedDict):
    """Subscription attributes."""

    IsActive: bool


class Subscription(SubAttributes):
    """User subscription."""

    ProjectDomain: str


def _get_user_create_op(user_email: str, project_domain: str) -> db.InsertArg:
    pk = db.PartitionKey(ent.User, user_email)
    sk = db.SortKey(ent.Sub, project_domain)
    attr: SubAttributes = {
        'IsActive': True
    }
    return db.InsertArg(pk, sk, attr)


def _get_trial_end_op(user_email: str, project_domain: str, trial_days: int) \
        -> db.InsertArg:
    trial_end = get_trial_end_date(trial_days)
    pk = db.PartitionKey(ent.TrialEnd, trial_end)
    # Concatenation of values ensures uniqueness of item.
    sk = db.SortKey(ent.TrialEnd, f'{user_email}|{project_domain}')
    return db.InsertArg(pk, sk)


def create(user_email: str, project_domain: str, trial_days: int) -> None:
    """Create a subscription to a project for a user.

    Args:
        user_email: User's email address that uniquely identifies them.
        project_domain: The project's domain name that uniquely identifies it.
        trial_days: The number of trial days for the project.

    Raises:
        `db.ConditionalCheckFailedError` if the subscription already exists.
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    # TODO (abiro) Stripe logic
    user_op = _get_user_create_op(user_email, project_domain)
    trial_end_op = _get_trial_end_op(user_email, project_domain, trial_days)
    get_table().transact_write_items([
        user_op,
        trial_end_op
    ])


def delete(user_email: str, project_domain: str) -> None:
    """Delete a subscription for a user.

    The subscription item is not removed from the database, but it's `IsActive`
    attribute is set to false.

    Args:
        user_email: User's email address that uniquely identifies them.
        project_domain: The project's domain name that uniquely identifies it.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    # TODO (abiro) Stripe logic
    pk = db.PartitionKey(ent.User, user_email)
    sk = db.SortKey(ent.Sub, project_domain)
    attr: SubAttributes = {
        'IsActive': False
    }
    get_table().update_attributes(pk, sk, attr)


def fetch(user_email: str, project_domain: str, consistent: bool = False) \
        -> Optional[SubAttributes]:
    """Fetch subscription attributes for a user.

    Args:
        user_email: User's email address that uniquely identifies them.
        project_domain: The project's domain name that uniquely identifies it.
        consistent: Whether the read should be strongly consistent.

    Returns:
        The subscription attributes if the subscription exists.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    pk = db.PartitionKey(ent.User, user_email)
    sk = db.SortKey(ent.Sub, project_domain)
    res = get_table().get(pk, sk,
                          consistent=consistent,
                          attributes=['IsActive'])
    if res is not None:
        return cast(SubAttributes, res)
    else:
        return None


def fetch_all(user_email: str, consistent: bool = False) -> List[Subscription]:
    """Fetch all subscriptions for a user.

    Args:
        user_email: User's email address that uniquely identifies them.
        consistent: Whether the read should be strongly consistent.

    Returns:
        The user's subscriptions.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    # TODO (abiro) add group subs as well
    pk = db.PartitionKey(ent.User, user_email)
    sk = db.PrefixSortKey(ent.Sub)
    subs = get_table().query_prefix(pk, sk,
                                    consistent=consistent,
                                    attributes=['SK', 'IsActive'])
    res = []
    for s in subs:
        r: Subscription = {
            'ProjectDomain': s['SK'],
            'IsActive': s['IsActive']
        }
        res.append(r)
    return res


def get_trial_end_date(trial_days: int) -> str:
    """Get the end date of a trial that is started today.

    Args:
        trial_days: The trial period in days.

    Returns:
        The date of the day after which trial has ended in UTC format, eg:
        "2020-02-15".

    """
    now = datetime.datetime.utcnow()
    # Make sure entire day is covered with + 1
    days = trial_days + 1
    delta = datetime.timedelta(days=days)
    end = now + delta
    return end.strftime('%Y-%m-%d')


def recreate(user_email: str, project_domain: str) -> None:
    """Recreate a subscription to a project for a user that has lapsed.

    There is no trial in this case.

    Args:
        user_email: User's email address that uniquely identifies them.
        project_domain: The project's domain name that uniquely identifies it.

    Raises:
        `db.DatabaseError` if there was an error connecting to the Database.

    """
    # TODO (abiro) Stripe logic
    # TODO (abiro) Update instead of Put
    pk = db.PartitionKey(ent.User, user_email)
    sk = db.SortKey(ent.Sub, project_domain)
    attr: SubAttributes = {
        'IsActive': True
    }
    get_table().update_attributes(pk, sk, attr)


def is_valid(user_email: str, project_domain: str) -> bool:
    """Verify whether a user has an active subscription to a project.

    Args:
        user_email: The user's email address.
        project_domain: The project's domain name.

    Returns:
        True if the user has an activate subscription to the project.

    """
    pk = db.PartitionKey(ent.User, user_email)
    sk_user = db.SortKey(ent.Sub, project_domain)
    sk_group = db.SortKey(ent.GroupSub, project_domain)

    pk_cond = cond.Key('PK').eq(str(pk))
    sk_cond = cond.Key('SK').eq(str(sk_user)) | cond.Key('SK').eq(str(sk_group))  # noqa 501
    key_cond = pk_cond & sk_cond

    query_arg = db.QueryArg(key_cond, attributes=['IsActive'])
    subs = get_table().query(query_arg)
    for s in subs:
        if s['IsActive']:
            return True
    else:
        return False

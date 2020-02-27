"""User session model."""
import hashlib
import time
from typing import Optional, TypedDict, cast

import dokklib_db as db

import app.common.models.entities as ent
from app.common.config import config
from app.common.models.db import get_table


class SessionAttributes(TypedDict):
    """Session attributes."""

    ExpiresAt: int


def _get_session_ttl() -> int:
    return round(time.time()) + config.session_cookie_max_age


def _hex_hash(value: bytes) -> str:
    """Get the SHA3-256 hex hash of the value.

    Args:
        value: The value to hash.

    Returns:
        The hash as a hex digest.

    """
    m = hashlib.sha3_256()
    m.update(value)
    return m.hexdigest()


def create(user_email: str, session_id: bytes) -> None:
    """Store the session id in the database.

    Args:
        user_email: User's email in Cognito.
        session_id: New session id.

    Raises:
        `db.ConditionalCheckFailedError` if the session id already exists.
        `db.DatabasError` if there was an error connecting to the database.

    """
    attributes: SessionAttributes = {
        'ExpiresAt': _get_session_ttl()
    }

    sess_hash = _hex_hash(session_id)
    pk = db.PartitionKey(ent.Session, sess_hash)
    sk_session = db.SortKey(ent.Session, sess_hash)
    sk_user = db.SortKey(ent.User, user_email)

    # We create a session entity in the database while creating a
    # SESSION-USER relation to make sure that there can be no duplicate
    # session ids in the database. Can not use conditions for this purpose,
    # as those require knowing the primary (composite) key which we don't
    # without querying the database.
    get_table().transact_write_items([
        db.InsertArg(pk, sk_session, attributes=attributes),
        db.InsertArg(pk, sk_user, attributes=attributes)
    ])


def delete(user_email: str, session_id: bytes) -> None:
    """Delete the session from the database.

    Args:
        user_email: User's email in Cognito.
        session_id: The session id.

    Raises:
        `db.DatabaseError` if there was an error connecting to the database.

    """
    sess_hash = _hex_hash(session_id)
    pk = db.PartitionKey(ent.Session, sess_hash)
    sk_session = db.SortKey(ent.Session, sess_hash)
    sk_user = db.SortKey(ent.User, user_email)

    # We create a session entity in the database while creating a
    # SESSION-USER relation to make sure that there can be no duplicate
    # session ids in the database. Can not use conditions for this purpose,
    # as those require knowing the primary (composite) key which we don't
    # without querying the database.
    get_table().transact_write_items([
        db.DeleteArg(pk, sk_session),
        db.DeleteArg(pk, sk_user)
    ])


def fetch_user_email(session_id: bytes) -> Optional[str]:
    """Fetch the user email based on the session from the database.

    Args:
        session_id: The session id.

    Returns:
        The user's email.

    Raises:
        `db.DatabaseError` if there was an error connecting to the database.

    """
    sess_hash = _hex_hash(session_id)
    pk = db.PartitionKey(ent.Session, sess_hash)
    sk = db.PrefixSortKey(ent.User)
    res = get_table().query_prefix(pk, sk, attributes=['SK'])
    if res:
        return cast(str, res[0]['SK'])
    else:
        return None

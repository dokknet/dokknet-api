"""Get session cookie for authorization from partner doc sites."""
import base64
import secrets
import time
import urllib.parse
from http.cookies import CookieError, SimpleCookie
from typing import Any, Dict, Optional, Type, cast

from botocore.exceptions import ClientError

import app.common.db as db
from app.common.config import config
from app.common.logging import get_logger
from app.common.token import AuthenticationError, TokenClient
from app.common.types.lambd import LambdaContext, ProxyEvent, ProxyResponse


_database = db.Database(config.main_table)
_log = get_logger(__name__)
_token_client = TokenClient(config.signing_key_name)


def _delete_handler(user_email: str, domain: str, headers: Dict[str, Any]) \
        -> ProxyResponse:
    delete_cookie = _get_cookie(domain, '', max_age=0)

    sess_id = get_session_id(headers)
    if sess_id is None:
        return _get_response(status=403, allow_origin=config.website_origin,
                             cookie=delete_cookie)

    try:
        _delete_session(user_email, sess_id)
    except ClientError as e:
        _log.error(f'Error deleting session:\n{e}')
        # Client should retry deleting the cookie for which they will need the
        # session id so don't delete the cookie.
        return _get_response(status=500, allow_origin=config.website_origin,
                             cookie=None)

    return _get_response(status=200, allow_origin=config.website_origin,
                         cookie=delete_cookie)


def _delete_session(user_email: str, session_id: bytes) -> None:
    """Delete the session from DynamoDB.

    Args:
        user_email: User's email in Cognito.
        session_id: The session id.

    Raises:
        app.common.db.ClientError if there was an error deleting the item (eg.
            connection error or session id doesn't exist).

    """
    _write_session(db.DeleteArg, user_email, session_id)


def _generate_id(nbytes: int) -> bytes:
    """Generate secure session id.

    Args:
        nbytes: Number of bytes in the id.

    Returns:
        The session id as a byte string.

    Raises:
        ValueError if nbytes is less than 16.

    """
    if nbytes < 16:
        raise ValueError(f'Minimum 16 bytes required to generate secure '
                         f'session id, instead got: ${nbytes} bytes.')
    return secrets.token_bytes(nbytes)


def _get_cookie(domain: str, token: str, max_age: int) -> str:
    # Safari strips values after '=' (which terminates b64, so it's important
    # to url-encode the token.
    encoded_token = urllib.parse.quote(token)
    # SameSite=None bc the intended use of this cookie is to allow
    # users to authenticate from other sites. Chrome will soon default to
    # SameSite=Lax, so it's important to set None explicitly.
    c = f'{config.session_cookie_name}={encoded_token} ' \
        f'Domain={domain}; ' \
        f'Max-Age={max_age}; ' \
        f'SameSite=None; Path=/; HttpOnly; Secure'
    return c


def _get_cookie_ttl() -> int:
    return round(time.time()) + config.session_cookie_max_age


def _get_handler(user_email: str, domain: str) -> ProxyResponse:
    sess_id = _generate_id(config.session_id_bytes)
    token = _get_session_token(sess_id)

    try:
        _store_session(user_email, sess_id)
    except ClientError as e:
        _log.error(f'Error storing session:\n{e}')
        return _get_response(status=500, allow_origin=config.website_origin,
                             cookie=None)

    cookie = _get_cookie(domain, token, config.session_cookie_max_age)
    return _get_response(status=200, allow_origin=config.website_origin,
                         cookie=cookie)


def _get_response(status: int, allow_origin: str,
                  cookie: Optional[str]) -> ProxyResponse:
    res = {
        'statusCode': status,
        'headers': {
            'Access-Control-Allow-Origin': allow_origin,
            'Access-Control-Allow-Credentials': True
        }
    }
    if cookie:
        res['multiValueHeaders'] = {
            'Set-Cookie': [cookie]
        }

    return cast(ProxyResponse, res)


def _get_session_from_token(token: str) -> bytes:
    """Get session id from a token and verify its signature.

    Verifying the signature of the session id only establishes its
    authenticity. Whether the session is still active must be verified by
    querying the database!

    Args:
        token: The token to extract session id from.

    Returns:
        The session id.

    Raises:
        app.token.AuthenticationError if the authenticity of the token can not
            be established.

    """
    message = _token_client.get_verified_payload(token)
    session_id = cast(str, message['sid'])
    return base64.b64decode(session_id)


def _get_session_token(session_id: bytes) -> str:
    # Signing the token allows us to verify that the session id was generated
    # on the server without hitting the database. This is useful for targeted
    # DDOS mitigation, but does not replace verifying that the session is
    # active in the DB.
    message = {
        # Session id may contain invalid utf-8 characters, so it must base64
        # encoded.
        'sid': base64.b64encode(session_id).decode('utf-8')
    }
    return _token_client.get_token(message, config.session_cookie_max_age)


def _store_session(user_email: str, session_id: bytes) -> None:
    """Store the session id in DynamoDB.

    Args:
        user_email: User's email in Cognito.
        session_id: New session id.

    Raises:
        app.common.db.ClientError if there was an error inserting the item (eg.
            connection error or session id exists).

    """
    attributes: db.Attributes = {
        'ExpiresAt': _get_cookie_ttl()
    }
    _write_session(db.InsertArg, user_email, session_id, attributes=attributes)


def _write_session(op_type: Type[db.OpArg], user_email: str, session_id: bytes,
                   attributes: Optional[db.Attributes] = None) -> None:
    sess_hash = _database.hex_hash(session_id)
    pk = db.PartitionKey('Session', sess_hash)
    sk_single = db.SingleSortKey('Session')
    sk_user = db.SortKey('User', user_email)

    # We create a session entity in the database before creating a
    # SESSION-USER relation to make sure that there can be no duplicate
    # session ids in the database. Can not use conditions for this purpose,
    # as those require knowing the primary (composite) key which we don't
    # without querying the database.
    if attributes:
        ops = [
            op_type(pk, sk_single, attributes=attributes),
            # DB has inverse secondary index for querying by email.
            op_type(pk, sk_user, attributes=attributes)
        ]
    else:
        ops = [
            op_type(pk, sk_single),
            op_type(pk, sk_user)
        ]

    _database.transact_write_items(ops)


def get_session_id(headers: Dict[str, Any]) -> Optional[bytes]:
    """Get session id from cookie.

    Args:
        headers: Lambda proxy event headers.

    Returns:
        The session id as bytes or None if it's not present or not valid.

    """
    try:
        raw_cookies = headers['Cookie']
    except KeyError:
        _log.debug('No cookie in headers')
        return None

    cookies: SimpleCookie[str] = SimpleCookie()
    try:
        cookies.load(raw_cookies)
    except CookieError:
        _log.debug('Invalid cookie in headers')
        return None
    try:
        session_token = cookies[config.session_cookie_name].value
    except KeyError:
        _log.debug('No session cookie in headers')
        return None

    try:
        unq_token = urllib.parse.unquote(session_token)
        return _get_session_from_token(unq_token)
    except AuthenticationError:
        _log.debug('Failed to authenticate token')
        return None


def handler(event: ProxyEvent, context: LambdaContext) -> ProxyResponse:
    """Get session cookie for authorization from partner doc sites."""
    # Error if authorizer is missing.
    authorizer = event['requestContext']['authorizer']
    user_email = authorizer['claims']['email']
    domain = event['requestContext']['domainName']
    http_method = event['httpMethod']

    if http_method == 'GET':
        return _get_handler(user_email, domain)
    elif http_method == 'DELETE':
        return _delete_handler(user_email, domain, event['headers'])
    else:
        # If an unsupported method is allowed to invoke this handler, that's a
        # misconfiguration in the Cloudformation template.
        raise RuntimeError(f'Method not allowed: {http_method}')

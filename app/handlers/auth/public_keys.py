# TODO (abiro) return JWK instead
"""Get a public key to verify tokens.

Path: /{stage}/auth/public-keys/{key_id}

See `PublicKeyResponse` for the response documentation.

"""
import base64
import json
from typing import TypedDict

from app.common.config import config
from app.common.path import get_name
from app.common.token import KeyNotFoundError, TokenClient
from app.common.types.lambd import LambdaContext, ProxyEvent, ProxyResponse


PATH_BASE = '/auth/public-keys/'

_token_client = TokenClient(config.signing_key_name)


class PublicKeysResponse(TypedDict):
    """Public keys API response.

    Attributes:
        keyId: The key id.
        publicKey: The public key as base64-encoded DER ASN.1 (not PEM, it's
            missing comment pre/suffixes).

    """

    keyId: str
    publicKey: str


def _get_error_response(status: int, message: str) -> ProxyResponse:
    response: ProxyResponse = {
        'statusCode': status,
        'body': message
    }
    return response


# TODO (abiro) add cache pragma for 24 hours
def _get_response(key_id: str) -> ProxyResponse:
    key_b = _token_client.fetch_public_key(key_id)
    key_b64 = base64.b64encode(key_b)
    key = key_b64.decode('utf-8')

    body = json.dumps({'publicKey': key, 'keyId': key_id})
    response: ProxyResponse = {
        'statusCode': 200,
        'body': body
    }
    return response


def handler(event: ProxyEvent, context: LambdaContext) -> ProxyResponse:
    """Get public key."""
    try:
        key_id = get_name(event['path'], PATH_BASE)
    except ValueError:
        msg = 'Invalid path. Expected: /{stage}/auth/public-keys/key-id'
        return _get_error_response(status=400, message=msg)

    try:
        return _get_response(key_id)
    except KeyNotFoundError:
        return _get_error_response(status=404, message='Public key not found')

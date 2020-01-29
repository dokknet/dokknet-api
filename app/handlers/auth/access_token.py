"""Get access token for authorization to partner doc sites."""
import json
from typing import Optional, cast

from app.common import db
from app.common.config import config
from app.common.path import get_name
from app.common.token import TokenClient
from app.common.types.lambd import AuthorizerEvent, AuthorizerResult, \
    LambdaContext, PolicyDocument, ProxyEvent, ProxyResponse
from app.handlers.auth.session_cookie import get_session_id


PATH_BASE = '/auth/access-token/'

_database = db.Database(config.main_table)
_token_client = TokenClient(config.signing_key_name)


def _fetch_user_email(session_id: bytes) -> Optional[str]:
    sess_id_hash = _database.hex_hash(session_id)
    pk = db.PartitionKey('Session', sess_id_hash)
    sk = db.PrefixSortKey('User')
    item = _database.fetch(pk, sk, attributes=['SK'])
    if item:
        return item['SK']
    else:
        return None


def _get_access_token(domain: str) -> str:
    message = {
        # Access token expires after ttl
        # Provides access to this domain
        'dom': domain
    }
    return _token_client.get_token(message, config.access_token_max_age)


def _get_handler(user_email: str, domain_name: str) -> ProxyResponse:
    origin = _get_origin(domain_name)
    if _verify_subscription(user_email, domain_name):
        token = _get_access_token(domain_name)
        body = json.dumps({'token': token})
        return _get_response(status=200, origin=origin, body=body)
    else:
        # Constrain origin to subscription domain_name for unauthorized
        # requests to prevent enumeration attack from other domain_names.
        return _get_response(status=403, origin=origin)


def _get_origin(domain_name: str) -> str:
    return f'https://{domain_name}'


def _get_response(status: int, origin: Optional[str] = None, body: str = '') \
        -> ProxyResponse:
    res: ProxyResponse = {
        'statusCode': status,
        'body': body
    }
    if origin:
        res['headers'] = {
            'Access-Control-Allow-Origin': origin
        }
    return res


def _options_handler(domain_name: str) -> ProxyResponse:
    res: ProxyResponse
    # Allowing CORS access for domains not in the database would open up a
    # JS-based DDOS attack vector.
    if _verify_domain(domain_name):
        origin = _get_origin(domain_name)
        headers = {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Max-Age': str(config.cors_ttl)
        }
        res = {
            'statusCode': 200,
            'headers': headers
        }
    else:
        res = {
            # Forbidden
            'statusCode': 403
        }
    return res


def _verify_domain(domain_name: str) -> bool:
    """Check whether a domain is in the database."""
    pk = db.PartitionKey('Domain', domain_name)
    sk = db.SingleSortKey('Domain')
    return _database.verify_key(pk, sk)


def _verify_subscription(user_email: str, domain_name: str) -> bool:
    pk = db.PartitionKey('User', user_email)
    sk = db.SortKey('Subscription', domain_name)
    return _database.verify_key(pk, sk)


def authorizer(event: AuthorizerEvent, context: LambdaContext) \
        -> AuthorizerResult:
    """Authorize API Gateway methods for the access token resource."""
    session_id = get_session_id(event['headers'])
    if session_id:
        user_email = _fetch_user_email(session_id)
    else:
        user_email = None

    effect = 'Allow' if user_email else 'Deny'
    principal_id = user_email if user_email else ''
    statement = {
        'Action': 'execute-api:Invoke',
        'Effect': effect,
        'Resource': event['methodArn']
    }
    document = {
        'Version': '2012-10-17',
        'Statement': [statement]
    }
    return {
        'principalId': principal_id,
        'policyDocument': cast(PolicyDocument, document)
    }


def handler(event: ProxyEvent, context: LambdaContext) -> ProxyResponse:
    """Get access token for authorization to partner doc sites."""
    auth_data = event['requestContext']['authorizer']
    user_email = auth_data['principalId']
    http_method = event['httpMethod']
    try:
        domain_name = get_name(event['path'], PATH_BASE)
    except ValueError:
        body = 'Invalid path. Expected: ' \
               '/{stage}/auth/access-token/www.example.com'
        # The response is to help developers CURLing the API.
        # No ACAO header, because origin='*' would open up a JS-based DDOS
        # attack vector.
        return _get_response(status=400, body=body)

    if http_method == 'GET':
        return _get_handler(user_email, domain_name)
    elif http_method == 'OPTIONS':
        return _options_handler(domain_name)
    else:
        # If an unsupported method is allowed to invoke this handler, that's a
        # misconfiguration in the Cloudformation template.
        raise RuntimeError(f'Method not allowed: {http_method}')

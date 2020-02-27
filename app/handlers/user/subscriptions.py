import json
from typing import Optional

import dokklib_db as db

from app.common.logging import get_logger
from app.common.models import Project, UserSub
from app.common.types.lambd import LambdaContext, ProxyEvent, ProxyResponse


_log = get_logger(__name__)


def _delete_handler(user_email: str, project_domain: str) -> ProxyResponse:
    UserSub.delete(user_email, project_domain)
    return _get_response(200)


def _get_handler(user_email: str) -> ProxyResponse:
    subs = UserSub.fetch_all(user_email)
    body = json.dumps({'subscriptions': subs})
    return _get_response(200, body)


def _get_response(status: int, body: Optional[str] = None) -> ProxyResponse:
    res: ProxyResponse = {
        'statusCode': status,
    }
    if body:
        res['body'] = body
    return res


def _put_handler(user_email: str, project_domain: str) -> ProxyResponse:
    project = Project.fetch(project_domain)
    if not project:
        return _get_response(404, 'Project doesn\'t exist')

    sub = UserSub.fetch(user_email, project_domain)
    if sub and sub['IsActive']:
        # Put is idempotent.
        return _get_response(200)
    elif sub:
        UserSub.recreate(user_email, project_domain)
    else:
        try:
            UserSub.create(user_email, project_domain, project['TrialDays'])
        except db.ConditionalCheckFailedError:
            # The subscription already exists.
            return _get_response(200)

    return _get_response(201)


def handler(event: ProxyEvent, context: LambdaContext) -> ProxyResponse:
    """Get, create or delete a user's subscription to a project."""
    authorizer = event['requestContext']['authorizer']
    user_email = authorizer['claims']['email']
    http_method = event['httpMethod']

    if http_method == 'DELETE':
        project_domain = event['pathParameters']['project_domain']
        return _delete_handler(user_email=user_email,
                               project_domain=project_domain)
    elif http_method == 'GET':
        return _get_handler(user_email=user_email)
    elif http_method == 'PUT':
        project_domain = event['pathParameters']['project_domain']
        return _put_handler(user_email=user_email,
                            project_domain=project_domain)
    else:
        # If an unsupported method is allowed to invoke this handler, that's a
        # misconfiguration in the Cloudformation template.
        raise RuntimeError(f'Method not allowed: {http_method}')

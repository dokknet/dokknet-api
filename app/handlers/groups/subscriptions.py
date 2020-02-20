from typing import Optional

import app.common.db as db
from app.common.logging import get_logger
from app.common.models import Group, GroupSub, Project
from app.common.types.lambd import LambdaContext, ProxyEvent, ProxyResponse


_log = get_logger(__name__)


def _delete_handler(user_email: str, project_domain: str) -> ProxyResponse:
    raise NotImplementedError


def _get_handler(user_email: str, group_name: str) -> ProxyResponse:
    raise NotImplementedError


def _get_response(status: int, body: Optional[str] = None) -> ProxyResponse:
    res: ProxyResponse = {
        'statusCode': status,
    }
    if body:
        res['body'] = body
    return res


def _put_handler(user_email: str, group_name: str, project_domain: str) \
        -> ProxyResponse:
    if not Group.is_owner(user_email, group_name):
        return _get_response(403, 'You are not the group owner.')

    project = Project.fetch(project_domain)
    if not project:
        return _get_response(404, 'Project doesn\'t exist.')

    group_sub = GroupSub.fetch(group_name, project_domain)
    if group_sub is not None and group_sub['IsActive']:
        return _get_response(200)

    if group_sub:
        # If group subscription exists, no trial then.
        GroupSub.recreate(group_name, project_domain)
    else:
        try:
            GroupSub.create(group_name, project_domain, project['TrialDays'])
        except db.ConditionalCheckFailedError:
            # Subscription already exists.
            return _get_response(200)

    return _get_response(201)


def handler(event: ProxyEvent, context: LambdaContext) -> ProxyResponse:
    """Get, create or delete a group's subscription to a project."""
    authorizer = event['requestContext']['authorizer']
    user_email = authorizer['claims']['email']
    group_name = event['pathParameters']['group_name']
    http_method = event['httpMethod']

    if http_method == 'DELETE':
        project_domain = event['pathParameters']['project_domain']
        return _delete_handler(user_email=user_email,
                               project_domain=project_domain)
    elif http_method == 'GET':
        return _get_handler(user_email=user_email,
                            group_name=group_name)
    elif http_method == 'PUT':
        project_domain = event['pathParameters']['project_domain']
        return _put_handler(user_email=user_email,
                            group_name=group_name,
                            project_domain=project_domain)
    else:
        # If an unsupported method is allowed to invoke this handler, that's a
        # misconfiguration in the Cloudformation template.
        raise RuntimeError(f'Method not allowed: {http_method}')

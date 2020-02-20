from typing import List, TypedDict

import boto3

from app.common.types.cognito import PostAuthEvent
from app.common.types.lambd import LambdaContext


_cognito_client = boto3.client('cognito-idp')


class _UserAttribute(TypedDict):
    Name: str
    Value: str


class _UpdateArgs(TypedDict):
    UserPoolId: str
    Username: str
    UserAttributes: List[_UserAttribute]


def handler(event: PostAuthEvent, _: LambdaContext) -> PostAuthEvent:
    """Cognito is_valid authentication challenge Lambda event handler."""
    request = event['request']
    email_verified = request['userAttributes'].get('email_verified', 'false')
    # Should throw if 'sub' is notpresent
    user_sub = request['userAttributes']['sub']
    if email_verified == 'false':
        # User has logged in with OTP delivered to email, so we can verify the
        # email now.
        user_pool_id = event['userPoolId']
        user_attrs = [{'Name': 'email_verified', 'Value': 'true'}]
        _cognito_client.admin_update_user_attributes(UserPoolId=user_pool_id,
                                                     Username=user_sub,
                                                     UserAttributes=user_attrs)

    return event

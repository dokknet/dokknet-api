# lambda is a reserved name in Python, hence the module name lambd
from typing import Any, Dict, List, Literal, Optional, Protocol, TypedDict


class _Identity(Protocol):
    cognito_identity_id: str
    cognito_identity_pool_id: str


class _Client(Protocol):
    installation_id: str
    app_title: str
    app_version_name: str
    app_version_code: str
    app_package_name: str


class _ClientContext(Protocol):
    """Client context that's provided to Lambda by the client application."""

    client: _Client
    custom: Dict[Any, Any]
    env: Dict[str, Any]


class LambdaContext(Protocol):
    """Lambda context object type.

    .. _AWS docs:
        https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html  # noqa 501

    """

    function_name: str
    function_version: str
    invoked_function_arn: str
    memory_limit_in_mb: str
    aws_request_id: str
    log_group_name: str
    log_stream_name: str
    identity: _Identity
    client_context: _ClientContext


# Can't use class syntax, bc `cognito:username` is an invalid name
_Claims = TypedDict('_Claims', {
    'aud': str,
    'auth_time': str,
    'cognito:username': str,
    'email': str,
    'email_verified': str,
    'event_id': str,
    'exp': str,
    'iat': str,
    'iss': str,
    'sub': str,
    'token_use': str
})


class _Authorizer(TypedDict, total=False):
    # Included if authorization type is COGNITO_USER_POOLS
    claims: _Claims
    # Included if authorization type is CUSTOM
    principalId: str


class _IdentityDict(TypedDict):
    apiKey: Optional[str]


class _RequestContext(TypedDict, total=False):
    authorizer: _Authorizer
    domainName: str
    identity: _IdentityDict


class _ProxyEventTotal(TypedDict):
    domainName: str
    httpMethod: str
    path: str
    headers: Dict[str, str]
    pathParameters: Dict[str, str]
    requestContext: _RequestContext
    queryStringParameters: Optional[Dict[str, str]]


class ProxyEvent(_ProxyEventTotal, total=False):
    """AWS Lambda API Gateway Proxy event.

    Only includes members used by the app.

    .. _AWS docs:
         https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html

    """

    # JSON string
    body: str
    multiValueHeaders: Dict[str, List[str]]


class ProxyResponse(TypedDict, total=False):
    """AWS Lambda API Gateway Proxy integration response.

    .. _AWS docs:
        https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html

    """

    isBase64Encoded: bool
    statusCode: int
    headers: Dict[str, str]
    multiValueHeaders: Dict[str, List[str]]
    body: str


class AuthorizerEvent(ProxyEvent):
    """AWS Lambda API Gateway Request Authorizer event.

    Only includes members used by the app.

    .. _AWS docs:
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html

    """

    methodArn: str


class _PolicyStatement(TypedDict):
    Action: Literal['execute-api:Invoke']
    Effect: Literal['Allow', 'Deny']
    Resource: str


class PolicyDocument(TypedDict):
    """API Gateway Lambda Authorizer policy document.

    Only includes members used by the app.

    .. _AWS docs:
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
    """

    Version: Literal['2012-10-17']
    Statement: List[_PolicyStatement]


class AuthorizerResult(TypedDict):
    """Output from an API Gateway Lambda Authorizer.

    Only includes members used by the app.

    .. _AWS docs:
        https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
    """

    principalId: str
    policyDocument: PolicyDocument

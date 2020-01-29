from typing import Dict, List, Literal, TypedDict


# BEGIN _TriggerEventBase
_TriggerSource = Literal[
    'PreSignUp_SignUp',
    'PreSignUp_ExternalProvider',
    'PostConfirmation_ConfirmSignUp',
    'PreAuthentication_Authentication',
    'PostAuthentication_Authentication',
    'CustomMessage_SignUp',
    'CustomMessage_AdminCreateUser',
    'CustomMessage_ResendCode',
    'CustomMessage_ForgotPassword',
    'CustomMessage_UpdateUserAttribute',
    'CustomMessage_VerifyUserAttribute',
    'CustomMessage_Authentication',
    'DefineAuthChallenge_Authentication',
    'CreateAuthChallenge_Authentication',
    'VerifyAuthChallengeResponse_Authentication',
    'PreSignUp_AdminCreateUser',
    'PostConfirmation_ConfirmForgotPassword',
    'TokenGeneration_HostedAuth',
    'TokenGeneration_Authentication',
    'TokenGeneration_NewPasswordChallenge',
    'TokenGeneration_AuthenticateDevice',
    'TokenGeneration_RefreshTokens',
    'UserMigration_Authentication',
    'UserMigration_ForgotPassword']


class _CallerContext(TypedDict):
    """The caller context."""

    awsSdkVersion: str
    clientId: str


class _RequestBase(TypedDict):
    """The request from the Amazon Cognito service."""

    userAttributes: Dict[str, str]


class _TriggerEventBase(TypedDict):
    """User Pool Lambda trigger event common parameters.

    Specific event types extend this class.

    .. _AWS docs for the event:
        https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html#cognito-user-pools-lambda-trigger-event-parameter-shared  # noqa 501
    .. _AWS docs for the trigger sources:
        https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html#cognito-user-identity-pools-working-with-aws-lambda-trigger-sources  # noqa 501

    """

    version: int
    region: str
    userPoolId: str
    userName: str
    callerContext: _CallerContext
# END _TriggerEventBase


# BEGIN PreSignUpEvent
class _PreSignUpRequestBase(_RequestBase):
    """Pre Sign-up Lambda Trigger Request."""

    validationData: Dict[str, str]
    clientMetadata: Dict[str, str]


class _PreSignUpResponse(TypedDict):
    """Pre Sign-up Lambda Trigger Response."""

    autoConfirmUser: bool
    autoVerifyEmail: bool
    autoVerifyPhone: bool


class PreSignUpEvent(_TriggerEventBase):
    """Pre Sign-up Lambda Trigger Event.

    .. _AWS docs:
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html  # noqa 501

    """

    request: _PreSignUpRequestBase
    response: _PreSignUpResponse
# END PreSignUpEvent


# BEGIN DefineAuthChallengeEvent
_ChallengeNames = Literal[
    'CUSTOM_CHALLENGE',
    'PASSWORD_VERIFIER',
    'SMS_MFA',
    'DEVICE_SRP_AUTH',
    'DEVICE_PASSWORD_VERIFIER',
    'ADMIN_NO_SRP_AUTH']


class _ChallengeResultTotal(TypedDict):
    challengeName: _ChallengeNames
    challengeResult: bool


class _ChallengeResult(_ChallengeResultTotal, total=False):
    # challengeMetaData is not guaranteed to be present
    challengeMetadata: str


class _DefineAuthChallengeRequest(_RequestBase):
    session: List[_ChallengeResult]
    clientMetadata: Dict[str, str]


class _DefineAuthChallengeResponseTotal(TypedDict):
    issueTokens: bool
    failAuthentication: bool


# Challenge name may not be present
class _DefineAuthChallengeResponse(_DefineAuthChallengeResponseTotal,
                                   total=False):
    challengeName: str


class DefineAuthChallengeEvent(_TriggerEventBase):
    """Define Auth Challenge Lambda Trigger Event.

    .. _AWS docs:
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-define-auth-challenge.html

    """

    request: _DefineAuthChallengeRequest
    response: _DefineAuthChallengeResponse
# END DefineAuthChallengeEvent


# BEGIN CreateAuthChallengeEvent
class _CreateAuthChallengeRequest(_DefineAuthChallengeRequest):
    challengeName: str


class _CreateAuthChallengeResponse(TypedDict):
    publicChallengeParameters: Dict[str, str]
    privateChallengeParameters: Dict[str, str]
    challengeMetadata: str


class CreateAuthChallengeEvent(_TriggerEventBase):
    """Create Auth Challenge Lambda Trigger Event.

    .. _AWS docs:
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-create-auth-challenge.html

    """

    request: _CreateAuthChallengeRequest
    response: _CreateAuthChallengeResponse
# END CreateAuthChallengeEvent


# BEGIN VerifyAuthChallenge
class _VerifyAuthChallengeRequest(_RequestBase):
    privateChallengeParameters: Dict[str, str]
    # Docs say challengeAnswer is Dict[str, str] as of 2019-11-26, but it is
    # actually str
    challengeAnswer: str
    clientMetadata: Dict[str, str]


class _VerifyAuthChallengeResponse(TypedDict):
    answerCorrect: bool


class VerifyAuthChallengeEvent(_TriggerEventBase):
    """Verify Auth Challenge Lambda Trigger Event.

    .. _AWS docs:
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-verify-auth-challenge-response.html

    """

    request: _VerifyAuthChallengeRequest
    response: _VerifyAuthChallengeResponse
# END VerifyAuthChallenge


# BEGIN PostAuthenticationEvent
class _PostAuthEventRequest(_RequestBase):
    newDeviceUsed: bool
    clientMetadata: Dict[str, str]


class _PostAuthEventResponse(TypedDict):
    pass


class PostAuthEvent(_TriggerEventBase):
    """Post Authentication Lambda Trigger Event.

    .. _AWS docs:
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-authentication.html
    """

    request: _PostAuthEventRequest
    response: _PostAuthEventResponse

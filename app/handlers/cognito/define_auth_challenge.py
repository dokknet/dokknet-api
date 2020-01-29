from app.common.types.cognito import DefineAuthChallengeEvent
from app.common.types.lambd import LambdaContext


def handler(event: DefineAuthChallengeEvent, _: LambdaContext) \
        -> DefineAuthChallengeEvent:
    """Cognito define authentication challenge Lambda event handler."""
    request = event['request']
    session = request['session']
    response = event['response']

    # User has provided wrong answer three times: fail authentication
    # Better do explicit equality check for boolean in case value is passed
    # as string (eg. "false").
    if len(session) >= 3 and session[-1]['challengeResult'] == False:  # noqa E712
        response['issueTokens'] = False
        response['failAuthentication'] = True
    # User has provided correct answer: authenticate
    elif len(session) > 0 and session[-1]['challengeResult'] == True:  # noqa E712
        response['issueTokens'] = True
        response['failAuthentication'] = False
    # User has not provided correct answer yet: present same challenge again
    else:
        response['issueTokens'] = False
        response['failAuthentication'] = False
        response['challengeName'] = 'CUSTOM_CHALLENGE'

    return event

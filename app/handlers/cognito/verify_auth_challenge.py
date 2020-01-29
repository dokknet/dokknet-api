from app.common.types.cognito import VerifyAuthChallengeEvent
from app.common.types.lambd import LambdaContext


def handler(event: VerifyAuthChallengeEvent, _: LambdaContext) \
        -> VerifyAuthChallengeEvent:
    """Cognito verify authentication challenge Lambda event handler."""
    request = event['request']
    otp = request['privateChallengeParameters']['otp']
    answer = request['challengeAnswer']

    response = event['response']
    response['answerCorrect'] = (answer == otp)

    return event

from app.common.types.cognito import PreSignUpEvent
from app.common.types.lambd import LambdaContext


def handler(event: PreSignUpEvent, _: LambdaContext) -> PreSignUpEvent:
    """Cognito pre-sign up Lambda event handler."""
    response = event['response']
    # User is set to verified, so they can log in immediately after receiving
    # an OTP. Email is confirmed in post-authentication lambda handler at
    # which point the user has proved that they have access to the email
    # address. Since emails must be unique, user accounts with unconfirmed
    # emails are removed by a cron job ensuring that email addresses can not
    # be squatted by users without access to the email.
    # TODO (abiro) add user to queue pre sign up with 5 min (?) delayed
    # delivery and remove if not email verified in that time frame.
    response['autoConfirmUser'] = True
    response['autoVerifyEmail'] = False

    return event

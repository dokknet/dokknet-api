import secrets
from urllib.parse import urlencode

import boto3

from app.common.config import config
from app.common.types.cognito import CreateAuthChallengeEvent
from app.common.types.lambd import LambdaContext


_ses_client = boto3.client('ses')


def _get_alphabet() -> str:
    """Get the one-time password alphabet.

    32-alphabet with lower-case characters. The alphabet excludes [ilov] as
    they can be confusing for humans.

    The purpose of this function is to verify alphabet usage of `_generate_otp`
    by mocking this function.

    Returns:
        The alphabet as a string

    """
    return '0123456789abcdefghjkmnpqrstuwxyz'


def _generate_otp(length: int) -> str:
    """Generate a one-time password.

    Uses a 32-alphabet with lower-case characters:
        '0123456789abcdefghjkmnpqrstuwxyz'
    The alphabet excludes [ilov] as they can be confusing for humans.

    Args:
        length: Length of the one-time password. Minimum 8.

    Returns:
        The one-time password with a hyphen in the middle, eg.: 'abcd-efgh'.

    Raises:
        ValueError if length is too short.

    """
    if length < 8:
        raise ValueError('Password length must be at least 8, instead it is: '
                         f'{length}')
    alphabet = _get_alphabet()
    chars = ''.join(secrets.choice(alphabet) for _ in range(length))
    middle = length // 2
    return f'{chars[:middle]}-{chars[middle:]}'


def _get_login_link(otp: str) -> str:
    query = urlencode({'otp': otp})
    return f'{config.login_page}?{query}'


def _get_text_template(otp: str) -> str:
    """Text email template for one-time password delivery."""
    login_link = _get_login_link(otp)

    # Ugly indentation, but this is the simplest solution to avoid leading
    # white space in multi-line strings.
    text = f"""\
Dokknet Paywall Login

Please click the link below to login:
{login_link}

Or enter your Dokknet one-time password on the login page:

{otp}

The password expires in 3 minutes and it only works in the same browser where \
you've requested it.

If you did not request this message, somebody else must have done so in your \
name.
If that's the case, you can safely ignore the message.

"""
    return text


def _get_html_template(otp: str) -> str:
    """HTML email template for one-time password delivery."""
    login_link = _get_login_link(otp)

    html = f"""\
<html>
<body>
<h3>Dokknet Paywall Login</h3>

<p>Please click the link below to login:</p>
<p>
    <strong>
        <a href="{login_link}" target="_blank">{login_link}</a>
    </strong>
</p>

<p>
    Or enter your Dokknet one-time password on the login page:</a>
</p>
<p>
    <strong style="-moz-user-select: all;-webkit-user-select: all;
        -ms-user-select: all;user-select: all;">
        {otp}
    </strong>
</p>

<p>The password expires in 3 minutes and it only works in the same browser
where you've requested it.</p>

<br/>

<p>
If you did not request this message, somebody else must have done so in your
name. If that's the case, you can safely ignore the message.
</p>

</body>
</html>
"""
    return html


def _send_email(address: str, otp: str) -> None:
    """Send email with one-time password via AWS SES.

    Args:
        address: Email address of the recipient.
        otp: One-time password.

    Raises:
        botocore.exceptions.ClientError on request error.

    """
    destination = {'ToAddresses': [address]}
    message = {
        'Subject': {
            'Data': 'Dokknet One-Time Password',
            'Charset': 'UTF-8'
        },
        'Body': {
            'Text': {
                'Data': _get_text_template(otp),
                'Charset': 'UTF-8'
            },
            'Html': {
                'Data': _get_html_template(otp),
                'Charset': 'UTF-8'
            }
        }
    }

    _ses_client.send_email(Source=config.ses_login_sender,
                           Destination=destination,
                           Message=message)


def handler(event: CreateAuthChallengeEvent, _: LambdaContext) \
        -> CreateAuthChallengeEvent:
    """Cognito create app challenge Lambda event handler."""
    request = event['request']
    sessions = request['session']
    email = request['userAttributes']['email']

    # New session. Generate code and send email
    if len(sessions) == 0:
        otp = _generate_otp(config.otp_length)
        _send_email(email, otp)
    # New invocation in existing session. Reuse one-time password from previous
    # invocation so that the user has a chance to correct wrong input without
    # requiring a new code (3 tries are allowed in define_auth_challenge).
    else:
        # challengeMetadata must be present, bc we just set it.
        prev_challenge = sessions[-1]['challengeMetadata']
        otp = prev_challenge[len('OTP-'):]

    response = event['response']
    response['publicChallengeParameters'] = {
        'email': email
    }
    response['privateChallengeParameters'] = {
        'otp': otp
    }
    response['challengeMetadata'] = f'OTP-{otp}'

    return event

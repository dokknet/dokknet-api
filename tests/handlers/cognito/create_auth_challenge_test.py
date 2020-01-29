from typing import Any, Dict, Tuple, cast
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import app.handlers.cognito.create_auth_challenge as m
from app.common.config import config
from app.common.types.cognito import CreateAuthChallengeEvent
from app.common.types.lambd import LambdaContext

from tests import TestBase


class TestGenerateOtp(TestBase):
    def test_alphabet_size(self):
        alphaset = set(m._get_alphabet())
        self.assertEqual(len(alphaset), 32)

    def test_invalid_length(self):
        with self.assertRaises(ValueError):
            m._generate_otp(length=0)

        with self.assertRaises(ValueError):
            m._generate_otp(length=-1)

        with self.assertRaises(ValueError):
            m._generate_otp(length=7)

    def test_otp_length(self):
        length = 8
        otp = m._generate_otp(length)
        # +1 for hyphen
        self.assertEqual(len(otp), length + 1)

    def test_hyphen(self):
        otp = m._generate_otp(length=8)
        self.assertEqual(otp[4], '-')

    @patch('app.handlers.cognito.create_auth_challenge._get_alphabet')
    def test_alphabet(self, get_alphabet):
        get_alphabet.return_value = 'a'
        otp = m._generate_otp(length=8)
        get_alphabet.assert_called_once()
        self.assertEqual(otp, 'aaaa-aaaa')

    @patch('secrets.choice')
    def test_uses_secrets(self, choice):
        choice.return_value = 'b'
        length = 8
        otp = m._generate_otp(length)
        self.assertEqual(choice.call_count, length)
        self.assertEqual(otp, 'bbbb-bbbb')


class TestGetLoginLink(TestBase):
    def test_has_otp(self):
        otp = 'ab12-34cd'
        link = m._get_login_link(otp)
        expected_link = f'{config.login_page}?otp={otp}'
        self.assertEqual(link, expected_link)


class TestSendEmail(TestBase):
    _to_patch = [
        'app.handlers.cognito.create_auth_challenge._ses_client'
    ]

    def _run_send_email(self, address: str = 'test@example.com',
                        otp: str = 'abcd-efgh') -> Dict[Any, Any]:
        ses_client = self._mocks['_ses_client']
        m._send_email(address, otp)
        ses_client.send_email.assert_called_once()
        params = cast(Dict[Any, Any], ses_client.send_email.call_args[1])
        return params

    def test_text_template(self):
        otp = 'abcd-1234'
        login_link = m._get_login_link(otp)
        text = m._get_text_template(otp)
        self.assertIn(login_link, text)

    def test_html_template(self):
        otp = 'abcd-7890'
        login_link = m._get_login_link(otp)
        html = m._get_text_template(otp)
        self.assertIn(login_link, html)

    def test_addresses(self):
        address = 'foo@bar.com'
        params = self._run_send_email(address=address)
        self.assertEqual(params['Source'], config.ses_login_sender)
        to_addresses = params['Destination']['ToAddresses']
        self.assertEqual(len(to_addresses), 1)
        self.assertEqual(to_addresses[0], address)

    @patch('app.handlers.cognito.create_auth_challenge._get_html_template')
    @patch('app.handlers.cognito.create_auth_challenge._get_text_template')
    def test_body(self, get_text_template, get_html_template):
        otp = '1234-abcd'
        text = 'text template'
        get_text_template.return_value = text
        html = 'html template'
        get_html_template.return_value = html
        params = self._run_send_email(otp=otp)
        get_html_template.assert_called_once_with(otp)
        get_text_template.assert_called_once_with(otp)
        self.assertEqual(params['Message']['Body']['Text']['Data'], text)
        self.assertEqual(params['Message']['Body']['Html']['Data'], html)


class TestCreateAuthChallenge(TestBase):
    _to_patch = [
        'app.handlers.cognito.create_auth_challenge._ses_client',
        'app.handlers.cognito.create_auth_challenge._generate_otp',
        'app.handlers.cognito.create_auth_challenge._send_email'
    ]

    def _get_args(self, empty_session: bool = False) \
            -> Tuple[CreateAuthChallengeEvent, LambdaContext]:
        event = cast(CreateAuthChallengeEvent,
                     self.get_event('create-auth-challenge'))
        if empty_session:
            event['request']['session'] = []
        context = MagicMock()
        return event, context

    def test_otp_generation(self):
        generate_otp = self._mocks['_generate_otp']

        event, context = self._get_args(empty_session=True)
        m.handler(event, context)
        generate_otp.assert_called_once_with(config.otp_length)

    def test_email_send(self):
        generate_otp = self._mocks['_generate_otp']
        send_email = self._mocks['_send_email']

        event, context = self._get_args(empty_session=True)
        email = event['request']['userAttributes']['email']
        otp = 'abcd-1234'
        generate_otp.return_value = otp
        res = m.handler(event, context)
        send_email.assert_called_once_with(email, otp)
        self.assertIs(res, event)

    def test_email_error(self):
        """Handler should raise if email service raises error."""
        send_email = self._mocks['_send_email']

        event, context = self._get_args(empty_session=True)
        send_email.side_effect = ClientError({}, {})
        with self.assertRaises(ClientError):
            m.handler(event, context)

    def test_reuse_otp(self):
        """Handler should reuse one-time password from previous attempt."""
        event, context = self._get_args()
        cm = event['request']['session'][-1]['challengeMetadata']
        otp = cm[len('OTP-'):]
        res = m.handler(event, context)
        self.assertIs(res, event)
        self.assertEqual(res['response']['privateChallengeParameters']['otp'],
                         otp)
        self.assertEqual(res['response']['challengeMetadata'], cm)

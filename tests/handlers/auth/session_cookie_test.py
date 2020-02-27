import base64
import urllib.parse
from http import cookies
from typing import Any
from unittest.mock import MagicMock as MMock
from unittest.mock import patch

import dokklib_db as db

from app.common.config import config
from app.common.token import AuthenticationError
from app.handlers.auth import session_cookie as m

from tests import TestBase


class MethodHandlerMixin:
    def setUp(self):
        super().setUp()
        self._email = 'foo@example.com'
        self._domain = 'www.example.com'


class TestDeleteHandler(MethodHandlerMixin, TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie.Session',
        'app.handlers.auth.session_cookie.get_session_id',
        'app.handlers.auth.session_cookie._log'
    ]

    def _call_test_fn(self, with_session=True):
        if with_session:
            self._mocks['get_session_id'].return_value = self._sess_id
        else:
            self._mocks['get_session_id'].return_value = None
        return m._delete_handler(self._email, self._domain, {})

    def _test_cookie(self, res, cookie):
        if cookie:
            self.assertListEqual(res['multiValueHeaders']['Set-Cookie'],
                                 [cookie])
        else:
            self.assertNotIn('multiValueHeaders', res)

    def setUp(self):
        super().setUp()
        self._sess_id = b'my-session-id'
        self._cookie = m._get_cookie(self._domain, '', max_age=0)

    def test_ok_cookie(self):
        res = self._call_test_fn()
        self._test_cookie(res, self._cookie)

    def test_no_session(self):
        res = self._call_test_fn(with_session=False)
        self.assertEqual(res['statusCode'], 403)
        self._test_cookie(res, self._cookie)

    def test_deletes_session(self):
        session_model = self._mocks['Session']

        self._call_test_fn()

        session_model.delete.assert_called_once_with(self._email,
                                                     self._sess_id)

    def test_handles_delete_error(self):
        session_model = self._mocks['Session']
        logging = self._mocks['_log']

        session_model.delete.side_effect = db.DatabaseError

        res = self._call_test_fn()
        self.assertEqual(res['statusCode'], 500)
        self._test_cookie(res, None)

        logging.error.assert_called_once()

    def test_ok_status(self):
        res = self._call_test_fn()
        self.assertEqual(res['statusCode'], 200)


class TestGenerateId(TestBase):
    def test_raises_on_short_bytes(self):
        with self.assertRaises(ValueError):
            m._generate_id(15)

    @patch('app.handlers.auth.session_cookie.secrets')
    def test_uses_secrets(self, secrets):
        nbytes = 16
        m._generate_id(nbytes)
        secrets.token_bytes.assert_called_with(nbytes)


class TestGetCookie(TestBase):
    def test_fields(self):
        # Important to test for '=' as it needs to be url-encoded.
        token = 'unit=.test=.data='
        domain = 'example.com'
        max_age = 100
        cookie_str = m._get_cookie(domain, token, max_age)
        # Mypy doesn't recognize cookies.SimpleCookie as a type.
        c: Any = cookies.SimpleCookie()
        c.load(cookie_str)
        morsel = c[config.session_cookie_name]
        self.assertEqual(morsel.value, urllib.parse.quote(token))
        self.assertEqual(morsel['domain'], domain)
        self.assertEqual(morsel['max-age'], str(max_age))
        self.assertEqual(morsel['samesite'], 'None')
        self.assertEqual(morsel['path'], '/')
        self.assertTrue(morsel['httponly'])
        self.assertTrue(morsel['secure'])


class TestGetSessionId(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._log'
    ]

    @staticmethod
    def _get_headers(cookie_val):
        headers = {}
        cookie = 'a=b; c=d;'
        if cookie_val:
            cookie += f' {config.session_cookie_name}={cookie_val}'
        headers['Cookie'] = cookie
        return headers

    def test_no_cookie(self):
        res = m.get_session_id({})
        self.assertEqual(res, None)

    def test_missing_cookie(self):
        event = self._get_headers(cookie_val=None)
        res = m.get_session_id(event)
        self.assertEqual(res, None)

    def test_invalid_cookie(self):
        headers = {
            'Cookie': 'invalid/cookie=value'
        }
        res = m.get_session_id(headers)
        self.assertEqual(res, None)

    @patch('app.handlers.auth.session_cookie._get_session_from_token')
    def test_auth_error(self, get_session_from_token):
        get_session_from_token.side_effect = AuthenticationError()
        event = self._get_headers(cookie_val='foo')
        res = m.get_session_id(event)
        get_session_from_token.assert_called_once()
        self.assertEqual(res, None)

    @patch('app.handlers.auth.session_cookie._get_session_from_token')
    def test_correct_session_token(self, get_session_from_token):
        sess_token = 'my=session=token'
        sess_token_q = urllib.parse.quote(sess_token)
        event = self._get_headers(cookie_val=sess_token_q)
        m.get_session_id(event)
        self.assertEqual(get_session_from_token.call_args.args[0], sess_token)

    @patch('app.handlers.auth.session_cookie._get_session_from_token')
    def test_verifies_session_id(self, get_session_from_token):
        sess_id = b'session-id'
        get_session_from_token.return_value = sess_id
        event = self._get_headers(cookie_val='foo')
        res = m.get_session_id(event)
        self.assertEqual(res, sess_id)


class TestGetVerifiedSessionToken(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._token_client'
    ]

    def test_message(self):
        token_client = self._mocks['_token_client']

        session_id = b'my-session-id'

        m._get_session_token(session_id)
        msg = {
            'sid': base64.b64encode(session_id).decode('utf-8')
        }
        token_client.get_token.assert_called_once_with(
            msg, config.session_cookie_max_age)


class TestGetVerifiedSessionId(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._token_client'
    ]

    # Important that the values are invalid utf-8 strings to catch related
    # errors.
    _session_id = b'3\x1aw\xf5\xb0m\xc9\x93U\x89\x82gxa\xdbg\t\xa5'

    def test_verifies_session_id(self):
        token_client = self._mocks['_token_client']
        get_verified_message = token_client.get_verified_payload

        token = 'my-token'
        session_id = b'my-session-id'
        get_verified_message.return_value = {
            'sid': base64.b64encode(session_id).decode('utf-8')
        }

        res = m._get_session_from_token(token)
        get_verified_message.assert_called_once_with(token)
        self.assertEqual(res, session_id)


class TestPostHandler(MethodHandlerMixin, TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie.Session',
        'app.handlers.auth.session_cookie._get_cookie',
        'app.handlers.auth.session_cookie._get_session_token',
        'app.handlers.auth.session_cookie._generate_id',
        'app.handlers.auth.session_cookie._log'
    ]

    def _call_test_fn(self):
        return m._post_handler(self._email, self._domain)

    def test_cookie(self):
        get_cookie = self._mocks['_get_cookie']
        get_session_token = self._mocks['_get_session_token']

        cookie = 'my-cookie'
        get_cookie.return_value = cookie
        token = 'my-token'
        get_session_token.return_value = token

        res = self._call_test_fn()

        cookie_headers = res['multiValueHeaders']['Set-Cookie']
        self.assertListEqual(cookie_headers, [cookie])
        get_cookie.assert_called_once_with(self._domain, token,
                                           config.session_cookie_max_age)

    def test_secure_id(self):
        generate_id = self._mocks['_generate_id']
        get_cookie = self._mocks['_get_cookie']
        get_session_token = self._mocks['_get_session_token']

        sid = b'my-session-id'
        token = 'my-token'
        generate_id.return_value = sid
        get_session_token.return_value = token

        self._call_test_fn()

        # Sanity check on config
        generate_id.assert_called_once_with(32)
        get_session_token.assert_called_once_with(sid)
        self.assertEqual(get_cookie.call_args.args[1], token)

    def test_stores_session(self):
        gen_id = self._mocks['_generate_id']
        session_model = self._mocks['Session']

        sid = b'my-session-id'
        gen_id.return_value = sid

        self._call_test_fn()

        session_model.create.assert_called_once_with(self._email, sid)

    def test_error_if_store_failed(self):
        session_model = self._mocks['Session']
        logging = self._mocks['_log']

        session_model.create.side_effect = db.DatabaseError

        res = self._call_test_fn()

        self.assertEqual(res['statusCode'], 500)
        logging.error.assert_called_once()

    def test_ok_status(self):
        res = self._call_test_fn()
        self.assertEqual(res['statusCode'], 201)


class TestHandler(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._post_handler',
        'app.handlers.auth.session_cookie._delete_handler',
    ]

    def _get_params(self, method, email, domain):
        event = self.get_event('api-proxy')
        event['httpMethod'] = method
        event['requestContext']['domainName'] = domain
        event['requestContext']['authorizer']['claims']['email'] = email
        return event, MMock()

    def setUp(self):
        super().setUp()
        self._email = 'foo@example.com'
        self._domain = 'www.example.com'

    def test_post(self):
        post_handler = self._mocks['_post_handler']
        m.handler(*self._get_params('POST', self._email, self._domain))
        post_handler.assert_called_once_with(self._email, self._domain)

    def test_delete(self):
        delete_handler = self._mocks['_delete_handler']
        event, context = self._get_params('DELETE', self._email, self._domain)
        m.handler(event, context)
        delete_handler.assert_called_once_with(self._email, self._domain,
                                               event['headers'])

    def test_unsupported_method(self):
        with self.assertRaises(RuntimeError):
            m.handler(*self._get_params('GET', self._email, self._domain))

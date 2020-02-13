import base64
from http import cookies
from typing import Any
from unittest.mock import MagicMock as MMock
from unittest.mock import patch

from botocore.exceptions import ClientError

import app.common.db as db
from app.common.config import config
from app.common.token import AuthenticationError
from app.handlers.auth import session_cookie as m

from tests import TestBase


class MethodHandlerMixin:
    def _test_cors(self, res, origin):
        headers = res['headers']
        acao_origin = headers['Access-Control-Allow-Origin']
        self.assertEqual(acao_origin, origin)
        self.assertTrue(headers['Access-Control-Allow-Credentials'])

    def setUp(self):
        super().setUp()
        self._email = 'foo@example.com'
        self._domain = 'www.example.com'

    def test_ok_status(self):
        res = self._call_test_fn()
        self.assertEqual(res['statusCode'], 200)

    def test_ok_cors(self):
        res = self._call_test_fn()
        self._test_cors(res, config.website_origin)


class TestDeleteHandler(MethodHandlerMixin, TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._delete_session',
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
        self._test_cors(res, config.website_origin)
        self._test_cookie(res, self._cookie)

    def test_deletes_session(self):
        delete_session = self._mocks['_delete_session']

        self._call_test_fn()

        delete_session.assert_called_once_with(self._email, self._sess_id)

    def test_handles_delete_error(self):
        delete_session = self._mocks['_delete_session']
        logging = self._mocks['_log']

        delete_session.side_effect = ClientError({}, '')

        res = self._call_test_fn()
        self.assertEqual(res['statusCode'], 500)
        self._test_cors(res, config.website_origin)
        self._test_cookie(res, None)

        logging.error.assert_called_once()


class TestDeleteSession(TestBase):
    @patch('app.handlers.auth.session_cookie._write_session')
    def test_calls_write(self, write_session):
        user_email = 'foo@example.com'
        session_id = b'session-id'

        m._delete_session(user_email, session_id)

        write_session.assert_called_once_with(db.DeleteArg,
                                              user_email,
                                              session_id)


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
        # Make token roughly as long as a signed token
        token = 'unit-test-token-data' * 10
        domain = 'example.com'
        max_age = 100
        cookie_str = m._get_cookie(domain, token, max_age)
        # Mypy doesn't recognize cookies.SimpleCookie as a type.
        c: Any = cookies.SimpleCookie()
        c.load(cookie_str)
        # Browser restriction + headroom.
        self.assertLess(len(cookie_str.encode('utf-8')), 3000)
        morsel = c[config.session_cookie_name]
        self.assertEqual(morsel.value, token)
        self.assertEqual(morsel['domain'], domain)
        self.assertEqual(morsel['max-age'], str(max_age))
        self.assertEqual(morsel['samesite'], 'None')
        self.assertEqual(morsel['path'], '/')
        self.assertTrue(morsel['httponly'])
        self.assertTrue(morsel['secure'])


class TestGetCookieTtl(TestBase):
    @patch('app.handlers.auth.session_cookie.config')
    @patch('app.handlers.auth.session_cookie.time')
    def test_correct_time(self, time, config):
        config.session_cookie_max_age = 101
        time.time.return_value = 1
        ttl = m._get_cookie_ttl()
        self.assertEqual(ttl, 102)


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
        sess_token = 'my-session-token'
        event = self._get_headers(cookie_val=sess_token)
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


class TestWriteSession(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._database'
    ]

    @staticmethod
    def _call_test_fn(user_email='foo@example.com',
                      session_id=b'test-session-id',
                      attributes=None):
        return m._write_session(db.InsertArg, user_email, session_id,
                                attributes=attributes)

    @patch('app.handlers.auth.session_cookie.db.PartitionKey')
    def test_stores_hash(self, pk_cls):
        hex_hash = self._mocks['_database'].hex_hash

        session_id = b'test-session-id'
        session_id_hash = 'my-session-id-hash'

        hex_hash.return_value = session_id_hash

        self._call_test_fn(session_id=session_id)

        hex_hash.assert_called_once_with(session_id)
        pk_cls.assert_called_once_with('Session', session_id_hash)

    @patch('app.handlers.auth.session_cookie._get_cookie_ttl')
    @patch('app.handlers.auth.session_cookie.db.InsertArg')
    def test_pk_and_attributes(self, insert_arg_cls, get_cookie_ttl):
        hex_hash = self._mocks['_database'].hex_hash

        expires_at = 123
        session_id_hash = 'my-session-id-hash'

        hex_hash.return_value = session_id_hash
        get_cookie_ttl.return_value = expires_at

        self._call_test_fn(attributes={'ExpiresAt': expires_at})

        self.assertEqual(insert_arg_cls.call_count, 2)
        for call in insert_arg_cls.call_args_list:
            pk = db.PartitionKey('Session', session_id_hash)
            self.assertEqual(call.args[0], pk)
            attributes = call.kwargs['attributes']
            self.assertEqual(attributes['ExpiresAt'], expires_at)

    @patch('app.handlers.auth.session_cookie.db.SingleSortKey')
    def test_session_sk(self, single_sk_cls):
        self._call_test_fn()
        single_sk_cls.assert_called_once_with('Session')

    @patch('app.handlers.auth.session_cookie.db.SortKey')
    def test_user_sk(self, sk_cls):
        user_email = 'foo@example.com'
        self._call_test_fn(user_email=user_email)
        sk_cls.assert_called_once_with('User', user_email)


class TestStoreSession(TestBase):
    @patch('app.handlers.auth.session_cookie._get_cookie_ttl')
    @patch('app.handlers.auth.session_cookie._write_session')
    def test_calls_write(self, write_session, get_cookie_ttl):
        user_email = 'foo@example.com'
        session_id = b'session-id'
        expires_at = 10
        get_cookie_ttl.return_value = expires_at

        m._store_session(user_email, session_id)

        attributes = {'ExpiresAt': expires_at}
        write_session.assert_called_once_with(db.InsertArg,
                                              user_email,
                                              session_id,
                                              attributes=attributes)


class TestGetHandler(MethodHandlerMixin, TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._get_cookie',
        'app.handlers.auth.session_cookie._store_session',
        'app.handlers.auth.session_cookie._get_session_token',
        'app.handlers.auth.session_cookie._generate_id',
        'app.handlers.auth.session_cookie._log'
    ]

    def _call_test_fn(self):
        return m._get_handler(self._email, self._domain)

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
        store_session = self._mocks['_store_session']

        sid = b'my-session-id'
        gen_id.return_value = sid

        self._call_test_fn()

        store_session.assert_called_once_with(self._email, sid)

    def test_error_if_store_failed(self):
        store_session = self._mocks['_store_session']
        logging = self._mocks['_log']

        store_session.side_effect = ClientError({}, 'op_name')

        res = self._call_test_fn()

        self.assertEqual(res['statusCode'], 500)
        logging.error.assert_called_once()


class TestHandler(TestBase):
    _to_patch = [
        'app.handlers.auth.session_cookie._get_handler',
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

    def test_get(self):
        get_handler = self._mocks['_get_handler']
        m.handler(*self._get_params('GET', self._email, self._domain))
        get_handler.assert_called_once_with(self._email, self._domain)

    def test_delete(self):
        delete_handler = self._mocks['_delete_handler']
        event, context = self._get_params('DELETE', self._email, self._domain)
        m.handler(event, context)
        delete_handler.assert_called_once_with(self._email, self._domain,
                                               event['headers'])

    def test_unsupported_method(self):
        with self.assertRaises(RuntimeError):
            m.handler(*self._get_params('POST', self._email, self._domain))

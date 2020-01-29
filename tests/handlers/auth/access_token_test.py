import json
from abc import ABC, abstractmethod
from typing import Optional, Tuple, cast
from unittest.mock import MagicMock

import app.common.db as db
from app.common.config import config
from app.common.types.lambd import AuthorizerEvent, AuthorizerResult, \
    ProxyEvent, ProxyResponse
from app.handlers.auth import access_token as m

from tests import TestBase


class TestFetchUserEmail(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token._database',
    ]

    def test_queries_with_hash(self):
        database = self._mocks['_database']

        sess_id = b'session-id'
        sess_id_hash = 'session-id-hash'
        database.hex_hash.return_value = sess_id_hash

        m._fetch_user_email(sess_id)
        database.hex_hash.assert_called_once_with(sess_id)
        pk = database.fetch.call_args.args[0]
        self.assertEqual(pk, f'SESSION#{sess_id_hash}')

    def test_handles_result(self):
        database = self._mocks['_database']

        user_email = 'foo@example.com'
        database.fetch.return_value = {'SK': user_email}

        res = m._fetch_user_email(b'sess_id')
        self.assertEqual(res, user_email)

    def test_handles_no_result(self):
        database = self._mocks['_database']

        database.fetch.return_value = None

        res = m._fetch_user_email(b'sess_id')
        self.assertEqual(res, None)


class TestGetAccessToken(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token._token_client',
    ]

    def test_message_format(self):
        domain = 'example.com'
        token_client = self._mocks['_token_client']
        m._get_access_token(domain)
        get_token = token_client.get_token
        get_token.assert_called_once_with({'dom': domain},
                                          config.access_token_max_age)


class TestGetHandler(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token._get_access_token',
        'app.handlers.auth.access_token._verify_subscription'
    ]

    def _check_response(self, response: ProxyResponse, status: int,
                        origin: str, body: str):
        self.assertEqual(response['statusCode'], status)
        acao = response['headers']['Access-Control-Allow-Origin']
        self.assertEqual(acao, origin)
        self.assertEqual(response['body'], body)

    def test_forbidden_on_missing_subscription(self):
        verify_subscription = self._mocks['_verify_subscription']
        verify_subscription.return_value = False

        user_email = 'foo@example.com'
        domain = 'docs.example.com'
        origin = m._get_origin(domain)
        res = m._get_handler(user_email, domain)
        self._check_response(res, status=403, origin=origin, body='')

    def test_allow_valid_subscription(self):
        verify_subscription = self._mocks['_verify_subscription']
        get_access_token = self._mocks['_get_access_token']

        user_email = 'foo@example.com'
        domain = 'docs.example.com'
        origin = m._get_origin(domain)
        token = 'my-token'
        body = json.dumps({'token': token})

        verify_subscription.return_value = True
        get_access_token.return_value = token

        res = m._get_handler(user_email, domain)
        self._check_response(res, status=200, origin=origin, body=body)
        verify_subscription.assert_called_once_with(user_email, domain)
        get_access_token.assert_called_once_with(domain)


class TestGetOrigin(TestBase):
    def test_uses_https(self):
        domain = 'www.example.com'
        origin = f'https://{domain}'
        self.assertEqual(m._get_origin(domain), origin)


class TestOptionsHandler(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token._verify_domain',
        'app.handlers.auth.access_token.config',
    ]

    def _check_response(self, response: ProxyResponse, status: int,
                        origin: Optional[str], cors_ttl: Optional[str]):
        self.assertEqual(response['statusCode'], status)
        if origin is not None and cors_ttl is not None:
            headers = response['headers']
            self.assertEqual(headers['Access-Control-Allow-Origin'], origin)
            self.assertEqual(headers['Access-Control-Allow-Credentials'],
                             'true')
            self.assertEqual(headers['Access-Control-Allow-Methods'],
                             'GET, OPTIONS')
            self.assertEqual(headers['Access-Control-Max-Age'], cors_ttl)

    def test_allows_valid_domain(self):
        config_mock = self._mocks['config']
        verify_domain = self._mocks['_verify_domain']

        cors_ttl = str(config.cors_ttl + 1)
        domain = 'docs.valid.com'
        origin = m._get_origin(domain)

        config_mock.cors_ttl = cors_ttl
        verify_domain.return_value = True

        res = m._options_handler(domain)
        self._check_response(res, status=200, origin=origin, cors_ttl=cors_ttl)

    def test_forbids_invalid_domain(self):
        verify_domain = self._mocks['_verify_domain']

        domain = 'docs.invalid.com'
        verify_domain.return_value = False

        res = m._options_handler(domain)
        self._check_response(res, status=403, origin=None, cors_ttl=None)


class VerifyKeyMixin(ABC):
    _to_patch = [
        'app.handlers.auth.access_token._database'
    ]

    _test_args = tuple()
    _test_kwargs = {}
    _pk = None
    _sk = None

    @abstractmethod
    def _call_test_fn(self, *args, **kwargs):
        raise NotImplementedError

    def test_correct_args(self):
        database = self._mocks['_database']

        self._call_test_fn(*self._test_args, **self._test_kwargs)
        database.verify_key.assert_called_once_with(self._pk, self._sk)

    def test_correct_res(self):
        database = self._mocks['_database']

        database.verify_key.return_value = True
        res_true = self._call_test_fn(*self._test_args, **self._test_kwargs)
        self.assertTrue(res_true)
        database.verify_key.return_value = False
        res_false = self._call_test_fn(*self._test_args, **self._test_kwargs)
        self.assertFalse(res_false)


class TestVerifyDomain(VerifyKeyMixin, TestBase):
    _test_args = ('docs.example.com',)
    _pk = db.PartitionKey('Domain', _test_args[0])
    _sk = db.SingleSortKey('Domain')

    def _call_test_fn(self, *args, **kwargs):
        return m._verify_domain(*args, **kwargs)


class TestVerifySubscription(VerifyKeyMixin, TestBase):
    _test_args = ('foo@example.com', 'docs.example.com',)
    _pk = db.PartitionKey('User', _test_args[0])
    _sk = db.SortKey('Subscription', _test_args[1])

    def _call_test_fn(self, *args, **kwargs):
        return m._verify_subscription(*args, **kwargs)


class TestAuthorizer(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token.get_session_id',
        'app.handlers.auth.access_token._fetch_user_email'
    ]

    def _check_effect(self, result: AuthorizerResult, expected_effect: str):
        statement = result['policyDocument']['Statement'][0]
        self.assertEqual(expected_effect, statement['Effect'])

    def _get_args(self) -> Tuple[AuthorizerEvent, MagicMock]:
        return self.get_event('request-authorizer'), MagicMock()

    def test_deny_no_session_id(self):
        get_session_id = self._mocks['get_session_id']

        get_session_id.return_value = None
        res = m.authorizer(*self._get_args())
        self._check_effect(res, 'Deny')
        self.assertEqual(res['principalId'], '')

    def test_deny_inactive_session(self):
        fetch_user_email = self._mocks['_fetch_user_email']

        fetch_user_email.return_value = None
        res = m.authorizer(*self._get_args())
        self._check_effect(res, 'Deny')
        self.assertEqual(res['principalId'], '')

    def test_allow_authorized(self):
        get_session_id = self._mocks['get_session_id']
        fetch_user_email = self._mocks['_fetch_user_email']

        session_id = b'session-id'
        get_session_id.return_value = session_id
        user_email = 'foo@example.com'
        fetch_user_email.return_value = user_email

        res = m.authorizer(*self._get_args())
        self._check_effect(res, 'Allow')
        self.assertEqual(res['principalId'], user_email)


class TestHandler(TestBase):
    _to_patch = [
        'app.handlers.auth.access_token._get_handler',
        'app.handlers.auth.access_token._options_handler'
    ]

    def _get_args(self, http_method, user_email, domain_name):
        event = self.get_event('api-proxy')
        event['httpMethod'] = http_method
        if domain_name:
            event['path'] = f'/auth/access-token/{domain_name}'
        else:
            event['path'] = f'/auth/access-token/'
        event['requestContext']['authorizer']['principalId'] = user_email
        return cast(ProxyEvent, event), MagicMock()

    def test_bad_request_on_missing_domain(self):
        user_email = 'foo@example.com'
        args = self._get_args(http_method='GET', user_email=user_email,
                              domain_name=None)
        res = m.handler(*args)
        self.assertEqual(res['statusCode'], 400)
        self.assertNotIn('headers', res)

    def test_get_dispatch(self):
        get_handler = self._mocks['_get_handler']

        domain_name = 'docs.example.com'
        user_email = 'foo@example.com'
        get_response = 'get-response'

        get_handler.return_value = get_response
        event, ctx = self._get_args(http_method='GET', user_email=user_email,
                                    domain_name=domain_name)

        res = m.handler(event, ctx)
        self.assertEqual(res, get_response)
        get_handler.assert_called_once_with(user_email, domain_name)

    def test_options_dispatch(self):
        options_handler = self._mocks['_options_handler']

        domain_name = 'docs.example.com'
        user_email = 'foo@example.com'
        options_response = 'options-response'

        options_handler.return_value = options_response

        event, ctx = self._get_args(http_method='OPTIONS',
                                    user_email=user_email,
                                    domain_name=domain_name)
        res = m.handler(event, ctx)
        self.assertEqual(res, options_response)
        options_handler.assert_called_once_with(domain_name)

    def test_error_unsupported_method(self):
        event, ctx = self._get_args(http_method='POST',
                                    user_email='foo@example.com',
                                    domain_name='example.com')
        with self.assertRaises(RuntimeError):
            m.handler(event, ctx)

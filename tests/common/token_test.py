from unittest.mock import patch

from botocore.exceptions import ClientError

import app.common.token as m

from tests import TestBase


class TestTokenBase(TestBase):

    _to_patch = [
        'app.common.token.boto3',
        'app.common.token.time'
    ]

    def setUp(self):
        super().setUp()

        time = self._mocks['time']
        time.time.return_value = 0

        self._aws_region = 'us-east-1'
        self._aws_account_id = '111122223333'
        self._kms_client = self._mocks['boto3'].client.return_value
        self._signing_key_name = 'my-signing-key-name'
        self._key_alias = f'alias/{self._signing_key_name}'
        self._key_id = 'b2bcaf69-2283-417d-a358-5f2f0399c249'
        arn = f'arn:aws:kms:{self._aws_region}:{self._aws_account_id}:' \
              f'key/{self._key_id}'
        self._key_arn = arn
        self._public_key_url_base = 'https://invalid.com/v1/auth/public-keys/'
        self._signing_key_url = self._public_key_url_base + self._key_id

        tc = m.TokenClient(self._signing_key_name,
                           aws_account_id=self._aws_account_id,
                           aws_region=self._aws_region,
                           public_key_url_base=self._public_key_url_base)
        self._token_client = tc

        self._algorithm = self._token_client.signing_algorithm
        self._max_age = 10
        self._expires_at = time.time.return_value + self._max_age
        self._header = {
            'alg': 'RS256',
            'typ': 'JWT',
            'kid': self._signing_key_url
        }
        self._payload = {
            'foo': 'bar',
            'baz': 1
        }
        payload = {**self._payload, **{'exp': self._expires_at}}
        self._payload_w_exp = payload
        self._payload_b64s = m.TokenClient._dict_to_url_b64s(payload)
        self._header_b64s = m.TokenClient._dict_to_url_b64s(self._header)
        self._message_b64s = f'{self._header_b64s}.{self._payload_b64s}'

        # Important that this is not valid utf-8
        self._signature = b'~\x95(Y\xa5\x8e{b'
        self._sig_b64s = m.TokenClient._bytes_to_url_b64s(self._signature)

        self._token = f'{self._message_b64s}.{self._sig_b64s}'


class TestFetchKeyId(TestTokenBase):

    def _setup_mock(self, key_id=None, aws_account_id=None):
        if key_id is None:
            key_id = self._key_id
        if aws_account_id is None:
            aws_account_id = self._aws_account_id
        res = {
            'KeyMetadata': {
                'AWSAccountId': aws_account_id,
                'KeyId': key_id
            }
        }
        self._kms_client.describe_key.return_value = res

    def test_returns_key_id(self):
        self._setup_mock()

        res = self._token_client._fetch_key_id(self._key_alias)
        self.assertEqual(res, self._key_id)

    def test_handles_client_error(self):
        self._kms_client.describe_key.side_effect = ClientError({}, 'name')

        with self.assertRaises(m.KeyNotFoundError):
            self._token_client._fetch_key_id(self._key_alias)

    def test_raises_on_account_id_mismatch(self):
        self._setup_mock(aws_account_id='foo')

        with self.assertRaises(m.KeyNotFoundError):
            self._token_client._fetch_key_id(self._key_alias)


class TestFetchPublicKey(TestTokenBase):

    def test_fetches_correct_key(self):
        public_key = 'my-public-key'
        res = {
            'PublicKey': public_key,
            'KeyUsage': 'SIGN_VERIFY'
        }
        self._kms_client.get_public_key.return_value = res

        res = self._token_client.fetch_public_key(self._key_id)
        self.assertEqual(res, public_key)

        key_id_arg = self._kms_client.get_public_key.call_args.kwargs['KeyId']
        self.assertEqual(key_id_arg, self._key_arn)

    def test_raises_if_key_doesnt_exist(self):
        class NotFoundException(Exception):
            pass
        kms = self._kms_client
        # Client exceptions are built at runtime by boto3.
        kms.exceptions.NotFoundException = NotFoundException
        kms.get_public_key.side_effect = NotFoundException

        with self.assertRaises(m.KeyNotFoundError):
            self._token_client.fetch_public_key(self._key_id)

    def test_raises_if_not_sign_key(self):
        kms = self._kms_client
        kms.get_public_key.return_value = {
            'KeyUsage': 'ENCRYPT_DECRYPT'
        }
        with self.assertRaises(m.KeyNotFoundError):
            self._token_client.fetch_public_key(self._key_id)

    def test_if_not_key_uuid(self):
        with self.assertRaises(m.KeyNotFoundError):
            self._token_client.fetch_public_key('my-key')


class TestetGetKeyIdFromArn(TestTokenBase):
    def test_empty(self):
        self.assertIsNone(m.TokenClient._get_key_id_from_arn(''))

    def test_id_only_no_match(self):
        key_id = '036a48aa-b3a0-4668-954d-af4196cf198c'

        res = m.TokenClient._get_key_id_from_arn(key_id)
        self.assertIsNone(res)

    def test_match(self):
        key_id = '036a48aa-b3a0-4668-954d-af4196cf198c'
        arn = f'arn:aws:kms:us-west-2:111122223333:key/{key_id}'

        res = m.TokenClient._get_key_id_from_arn(arn)
        self.assertEqual(res, key_id)

    def test_checks_valid_uuid(self):
        key_id = '036a48aa-b3a0-954d-af4196cf198c'
        arn = f'arn:aws:kms:us-west-2:111122223333:key/{key_id}'

        res = m.TokenClient._get_key_id_from_arn(arn)
        self.assertIsNone(res)

    def test_match_all_regions(self):
        key_id = '036a48aa-b3a0-4668-954d-af4196cf198c'
        arn = f'arn:aws:kms:eu-central-1:111122223333:key/{key_id}'

        res = m.TokenClient._get_key_id_from_arn(arn)
        self.assertEqual(res, key_id)


class TestGetToken(TestTokenBase):

    _to_patch = ['app.common.token.TokenClient.signing_key_id#PROPERTY'] \
        + TestTokenBase._to_patch

    def setUp(self):
        super().setUp()
        self._kms_client.sign.return_value = {
            'Signature': self._signature,
            'KeyId': self._signing_key_url,
            'SigningAlgorithm': self._algorithm
        }
        self._mocks['signing_key_id'].return_value = self._key_id

    def test_token_format(self):
        token = self._token_client.get_token(self._payload, self._max_age)

        header, payload, signature = token.split('.')
        self.assertEqual(header, self._header_b64s)
        self.assertEqual(payload, self._payload_b64s)
        self.assertEqual(signature, self._sig_b64s)

    def test_token_signature(self):
        token = self._token_client.get_token(self._payload, self._max_age)

        self._kms_client.sign.assert_called_once_with(
            KeyId=self._key_alias,
            Message=self._message_b64s.encode('utf-8'),
            MessageType='RAW',
            SigningAlgorithm=self._token_client.signing_algorithm
        )
        _, _, sign_b64s = token.split('.')
        self.assertEqual(sign_b64s, self._sig_b64s)

    def test_header(self):
        token = self._token_client.get_token(self._payload, self._max_age)

        header_b64s, _, _ = token.split('.')
        header = m.TokenClient._url_b64s_to_dict(header_b64s)
        self.assertDictEqual(header, self._header)
        self.assertEqual(header['typ'], 'JWT')
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], self._signing_key_url)

    def test_payload(self):
        token = self._token_client.get_token(self._payload, self._max_age)

        _, payload_b64s, _ = token.split('.')
        payload = m.TokenClient._url_b64s_to_dict(payload_b64s)
        self.assertDictEqual(payload, self._payload_w_exp)
        # Check that `get_token` doesn't mutate payload arg.
        self.assertNotIn('exp', self._payload)

    def test_raises_on_invalid_signing_key(self):
        self._mocks['signing_key_id'].side_effect = m.KeyNotFoundError('')
        with self.assertRaises(m.KeyNotFoundError):
            self._token_client.get_token(self._payload, self._max_age)

    def test_raises_on_exp_key(self):
        with self.assertRaises(ValueError):
            self._token_client.get_token({'exp': 'foo'}, 1)


class TestGetVerifiedPayload(TestTokenBase):
    _to_patch = ['app.common.token.TokenClient._verify_signature'] \
        + TestTokenBase._to_patch

    def test_raises_on_invalid_format(self):
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload('abcd.efgh')

    def test_raises_on_invalid_header(self):
        token = f'foo.{self._payload_b64s}.{self._sig_b64s}'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_missing_kid(self):
        del self._header['kid']
        header_b64s = m.TokenClient._dict_to_url_b64s(self._header)
        token = f'{header_b64s}.{self._payload_b64s}.{self._sig_b64s}'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_invalid_kid(self):
        self._header['kid'] = self._key_arn
        header_b64s = m.TokenClient._dict_to_url_b64s(self._header)
        token = f'{header_b64s}.{self._payload_b64s}.{self._sig_b64s}'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_invalid_b64_signature(self):
        token = f'{self._header_b64s}.{self._payload_b64s}.foo'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_invalid_signature(self):
        self._mocks['_verify_signature'].side_effect = m.AuthenticationError
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(self._token)

    def test_raises_on_invalid_b64_payload(self):
        token = f'{self._header_b64s}.foo.{self._sig_b64s}'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_missing_exp(self):
        payload_b64s = m.TokenClient._dict_to_url_b64s(self._payload)
        token = f'{self._header_b64s}.{payload_b64s}.{self._sig_b64s}'
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(token)

    def test_raises_on_expired_token(self):
        self._mocks['time'].time.return_value = self._expires_at + 1
        with self.assertRaises(m.AuthenticationError):
            self._token_client.get_verified_payload(self._token)

    def test_verifies_signature(self):
        verify_signature = self._mocks['_verify_signature']
        self._token_client.get_verified_payload(self._token)
        verify_signature.assert_called_once_with(self._message_b64s,
                                                 self._signature,
                                                 self._key_id)

    def test_returns_payload(self):
        res = self._token_client.get_verified_payload(self._token)
        self.assertDictEqual(res, self._payload_w_exp)


class TestUtils(TestTokenBase):

    def test_url_b64s_to_bytes(self):
        with self.assertRaises(m._ParseError):
            m.TokenClient._url_b64s_to_bytes('xyz')

    def test_json_parse_error(self):
        with self.assertRaises(m._ParseError):
            m.TokenClient._url_b64s_to_dict('')

    def test_dict_to_url_b64s(self):
        message_b64s = m.TokenClient._dict_to_url_b64s(self._payload)
        message_re = m.TokenClient._url_b64s_to_dict(message_b64s)
        self.assertDictEqual(message_re, self._payload)

    def test_valid_key_id_passes(self):
        self.assertTrue(m.TokenClient._is_valid_key_id(self._key_id))

    def test_invalid_key_id_fails(self):
        self.assertFalse(m.TokenClient._is_valid_key_id(self._key_arn))

    def test_signing_key_name(self):
        self.assertEqual(self._token_client.signing_key_name,
                         self._signing_key_name)

    def test_signing_algorithm(self):
        # Better make double sure this doesn't change.
        self.assertEqual(self._token_client.signing_algorithm,
                         'RSASSA_PKCS1_V1_5_SHA_256')

    def test_signing_key_alias(self):
        self.assertEqual(self._token_client.signing_key_alias, self._key_alias)

    def test_get_key_arn(self):
        arn = self._token_client._get_key_arn(self._key_id)
        self.assertEqual(arn, self._key_arn)

    def test_get_arn_raises_on_invalid_key(self):
        with self.assertRaises(ValueError):
            self._token_client._get_key_arn(self._key_arn)

    @patch('app.common.token.TokenClient._fetch_key_id')
    def test_signing_key_id(self, fetch_key_id):
        fetch_key_id.return_value = self._key_id
        key_id = self._token_client.signing_key_id

        fetch_key_id.assert_called_once_with(self._key_alias)
        self.assertEqual(key_id, self._key_id)


class TestVerifySignature(TestTokenBase):
    def test_verifies_signature(self):
        kms = self._kms_client
        token_client = self._token_client

        message = 'message-b64'
        signature = b'my-signature'

        token_client._verify_signature(message, signature, self._key_id)
        kms.verify.assert_called_once_with(
            KeyId=self._key_arn,
            Message=message.encode('utf-8'),
            Signature=signature,
            SigningAlgorithm=self._algorithm
        )

    def test_raises_on_invalid_key_arn(self):
        message = 'message-b64'
        signature = b'my-signature'

        with self.assertRaises(m.AuthenticationError):
            self._token_client._verify_signature(message, signature,
                                                 self._key_arn)

    def test_raises_on_client_error(self):
        kms = self._kms_client
        token_client = self._token_client

        message = 'message-b64'
        signature = b'my-signature'

        kms.verify.side_effect = ClientError({}, '')

        with self.assertRaises(m.AuthenticationError):
            token_client._verify_signature(message, signature, self._key_id)

    def test_raises_on_invalid_signature(self):
        kms = self._kms_client
        token_client = self._token_client

        message = 'message-b64'
        signature = b'my-signature'

        kms.verify.return_value = {
            'SignatureValid': False
        }

        with self.assertRaises(m.AuthenticationError):
            token_client._verify_signature(message, signature, self._key_id)

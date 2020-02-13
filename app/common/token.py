"""Generate or verify JWT tokens.

Signing algorithm: RS256.

We don't use a JWT library to generate the tokens, because we want to keep the
secret key in AWS KMS.

"""
import base64
import binascii
import copy
import json
import re
import time
from typing import Any, Dict, Literal, Optional, TypedDict, cast

import boto3

from botocore.exceptions import ClientError

from app.common.config import config
from app.common.logging import get_logger


_StrDict = Dict[str, Any]


class TokenHeader(TypedDict):
    """Token header type.

    Attributes:
        alg: The signing algorithm (always RS256).
        typ: The token type (always JWT).
        kid: The key id which is a fully qualified url of the public key.
            (eg.: https://dokknet-api.com/v1/auth/public-keys/{uuid})

    """

    alg: Literal['RS256']
    typ: Literal['JWT']
    kid: str


class AuthenticationError(Exception):
    """Token signature can not be verified."""

    def __init__(self) -> None:
        """Initialize an AuthenticationError instance."""
        # Important that the error message is always the same.
        super().__init__(self.__doc__)


class KeyNotFoundError(Exception):
    """Key was not found in AWS KMS."""

    def __init__(self, key_id: str) -> None:
        """Initialize a KeyNotFoundError instance."""
        # Important that the error message is always the same.
        super().__init__(f'Key not found: {key_id}')


class _ParseError(Exception):
    """Raised if data can not be parsed."""


class TokenClient:
    """Generate signed tokens or verify them.

    The implementation is NOT thread-safe.

    """

    @staticmethod
    def _bytes_to_url_b64s(b: bytes) -> str:
        message_b64s = base64.urlsafe_b64encode(b)
        return message_b64s.decode('utf-8')

    @staticmethod
    def _dump_canonical(d: _StrDict) -> str:
        # Custom separators remove white space.
        return json.dumps(d, sort_keys=True, separators=(',', ':'))

    @staticmethod
    def _get_expiry(max_age: int) -> int:
        return round(time.time() + max_age)

    @staticmethod
    def _get_key_alias(key_name: str) -> str:
        return f'alias/{key_name}'

    @staticmethod
    def _is_valid_key_id(key_id: str) -> bool:
        # UUID regex
        p = r'\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b'  # noqa 501
        # Compiled regexes are cached
        match = re.fullmatch(p, key_id, flags=re.IGNORECASE)
        return bool(match)

    @staticmethod
    def _url_b64s_to_bytes(s: str) -> bytes:
        try:
            return base64.urlsafe_b64decode(s.encode('utf-8'))
        except binascii.Error:
            raise _ParseError()

    @classmethod
    def _dict_to_url_b64s(cls, message: _StrDict) -> str:
        message_s = cls._dump_canonical(message)
        return cls._str_to_url_b64s(message_s)

    @classmethod
    def _str_to_url_b64s(cls, s: str) -> str:
        return cls._bytes_to_url_b64s(s.encode('utf-8'))

    @classmethod
    def _url_b64s_to_dict(cls, b64_json: str) -> _StrDict:
        try:
            bin_json = cls._url_b64s_to_bytes(b64_json)
            return cast(_StrDict, json.loads(bin_json))
        except json.JSONDecodeError:
            raise _ParseError()

    @classmethod
    def _get_key_id_from_arn(cls, key_arn: str) -> Optional[str]:
        p = r'arn:aws:kms:[a-z0-9\-]+:[0-9]+:key/([a-f0-9\-]+)'
        match = re.match(p, key_arn, re.IGNORECASE)
        if match and cls._is_valid_key_id(match.group(1)):
            return match.group(1)
        else:
            return None

    def __init__(self, signing_key_name: str,
                 aws_account_id: str = config.aws_account_id,
                 aws_region: str = config.aws_region,
                 public_key_url_base: str = config.public_key_url_base):
        """Initialize a TokenClient instance.

        Args:
            signing_key_name: The alias name of the key used for signing token
                in AWS KMS (ie. not including the "alias/" prefix).
            aws_account_id: The AWS account id where the KMS keys live.
            aws_region: The AWS region where the KMS keys live.
            public_key_url_base: Eg.:
                "https://dokknet-api.com/v1/auth/public-keys/"

        """
        self._log = get_logger(f'{__name__}.{self.__class__.__name__}')
        self._client = boto3.client('kms')

        self._signing_key_name = signing_key_name
        self._signing_key_alias = self._get_key_alias(self._signing_key_name)
        self._signing_key_id: Optional[str] = None
        self._public_key_url_base = public_key_url_base

        self._public_keys: Dict[str, bytes] = {}
        self._aws_account_id = aws_account_id
        self._aws_region = aws_region

    @property
    def signing_algorithm(self) -> str:
        """Get the signing algorithm."""
        # ECDSA is too expensive in AWS KMS.
        return 'RSASSA_PKCS1_V1_5_SHA_256'

    @property
    def jwt_algorithm(self) -> Literal['RS256']:
        """Get the JWT signing algorithm name."""
        return 'RS256'

    @property
    def signing_key_alias(self) -> str:
        """Get the signing key alias."""
        return self._signing_key_alias

    @property
    def signing_key_id(self) -> str:
        """Get the signing key id."""
        if self._signing_key_id is None:
            self._signing_key_id = self._fetch_key_id(self.signing_key_alias)
        return self._signing_key_id

    @property
    def signing_key_name(self) -> str:
        """Get the signing key name."""
        return self._signing_key_name

    @property
    def signing_key_url(self) -> str:
        """Get the signing key name."""
        return self._public_key_url_base + self.signing_key_id

    @property
    def token_type(self) -> Literal['JWT']:
        """Get the token type."""
        return 'JWT'

    def _get_key_arn(self, key_id: str) -> str:
        if not self._is_valid_key_id(key_id):
            raise ValueError(f'Invalid key id: {key_id}')

        region = self._aws_region
        account_id = self._aws_account_id
        return f'arn:aws:kms:{region}:{account_id}:key/{key_id}'

    def _get_key_id_from_url(self, url: str) -> str:
        # Raises ValueError if url base is not in url
        _, key_id = url.split(self._public_key_url_base)
        return key_id

    def _fetch_key_id(self, key_alias: str) -> str:
        try:
            res = self._client.describe_key(KeyId=key_alias)
        except ClientError:
            raise KeyNotFoundError(key_alias)

        key_meta = res['KeyMetadata']
        # Although this method is not expected to be called with user input,
        # we still check that key_alias was not a key ARN, because that
        # would allow an attacker to make use use their keys as our own.
        if key_meta['AWSAccountId'] != self._aws_account_id:
            raise KeyNotFoundError(key_alias)

        return cast(str, key_meta['KeyId'])

    def _fetch_public_key(self, key_id: str) -> bytes:
        try:
            key_arn = self._get_key_arn(key_id)
        except ValueError:
            raise KeyNotFoundError(key_id)

        try:
            # It's critical to query with key ARN, otherwise attacker could
            # supply their own ARN, grant us permission to read and we would
            # return their public key as our own.
            res = self._client.get_public_key(KeyId=key_arn)
        except self._client.exceptions.NotFoundException:
            raise KeyNotFoundError(key_id)

        if res['KeyUsage'] == 'SIGN_VERIFY':
            return cast(bytes, res['PublicKey'])
        else:
            raise KeyNotFoundError(key_id)

    # TODO (abiro) do verification locally
    def _verify_signature(self, message: str, signature: bytes, key_id: str) \
            -> None:
        try:
            key_arn = self._get_key_arn(key_id)
        except ValueError:
            self._log.debug('Invalid key id')
            raise AuthenticationError()

        try:
            # It's critical to verify with ARN, otherwise attacker could pass
            # their own key ARN as key id, grant our account permission to
            # verify, and thus trivially bypass token verification.
            res = self._client.verify(
                KeyId=key_arn,
                Message=message.encode('utf-8'),
                Signature=signature,
                SigningAlgorithm=self.signing_algorithm
            )
        except ClientError:
            self._log.debug('Error verifying key')
            raise AuthenticationError()
        # boto3 documentation says `SignatureValid` is either true or an
        # exception is raised, but better check the value anyway in case
        # the behaviour changes.
        if not res['SignatureValid']:
            self._log.debug('Invalid signature')
            raise AuthenticationError()

    def fetch_public_key(self, key_id: str) -> bytes:
        """Fetch public key by id from KMS.

        Args:
            key_id: The public key id (from the `key` field of the token).

        Returns:
            The public key as DER ASN.1 bytes.

        Raises:
            `app.token.KeyNotFoundError` if the key doesn't exist or it's not
                for signatures.
            `botocore.exceptions.ClientError` if there was a problem reaching
                AWS KMS.

        """
        if key_id not in self._public_keys:
            self._public_keys[key_id] = self._fetch_public_key(key_id)

        return self._public_keys[key_id]

    def get_token(self, payload: _StrDict, max_age: int) -> str:
        """Generate a JWT token.

        The payload will be automatically added an `exp` field that is set to
        `round(time.time() + max_age)`.

        Args:
            payload: The message to sign. The bas64 encoded JSON
                representation of the message may not be greater than 4096
                bytes.
            max_age: The maximum age of the token from now in seconds.

        Returns:
            The JWT token.


        Raises:
            botocore.exceptions.ClientError if there was a problem reaching
                AWS KMS.
            ValueError if `message` has an `exp` key or KeyId from KMS is not
                an ARN

        """
        if 'exp' in payload:
            raise ValueError('Payload must not contain `exp` field.')
        payload = copy.deepcopy(payload)
        payload['exp'] = self._get_expiry(max_age)

        header = {
            'alg': self.jwt_algorithm,
            'typ': self.token_type,
            'kid': self.signing_key_url
        }

        header_b64_url = self._dict_to_url_b64s(header)
        payload_b64_url = self._dict_to_url_b64s(payload)
        message = f'{header_b64_url}.{payload_b64_url}'
        message_b = message.encode('utf-8')

        response = self._client.sign(
            KeyId=self.signing_key_alias,
            Message=message_b,
            MessageType='RAW',
            SigningAlgorithm=self.signing_algorithm
        )
        sig_b64s = self._bytes_to_url_b64s(response['Signature'])
        token = f'{message}.{sig_b64s}'
        return token

    def get_verified_payload(self, token: str) -> _StrDict:
        """Get payload from a token and verify its signature.

        Args:
            token: The JWT token string.

        Returns:
            The payload dict.

        Raises:
            app.token.AuthenticationError if the authenticity of the token can
                not be established.

        """
        # It's important that the same error is raised no matter why the
        # verification failed.
        try:
            message_b64s, sig_b64s = token.rsplit('.', maxsplit=1)
            header_b64s, payload_b64s = message_b64s.split('.')
        except ValueError:
            self._log.debug('Token string is not in JWT format')
            raise AuthenticationError()

        try:
            header = self._url_b64s_to_dict(header_b64s)
        except _ParseError:
            self._log.debug('Failed to parse header')
            raise AuthenticationError()

        try:
            kid = header['kid']
        except KeyError:
            self._log.debug('No kid field in header')
            raise AuthenticationError()

        try:
            key_id = self._get_key_id_from_url(kid)
        except ValueError:
            self._log.debug('Invalid key url')
            raise AuthenticationError()

        try:
            signature = self._url_b64s_to_bytes(sig_b64s)
        except _ParseError:
            self._log.debug('Invalid base64 in signature')
            raise AuthenticationError()

        # Raises `AuthenticationError` on invalid signature.
        self._verify_signature(message_b64s, signature, key_id)

        try:
            payload = self._url_b64s_to_dict(payload_b64s)
        except _ParseError:
            self._log.debug('Failed to parse payload')
            raise AuthenticationError()

        try:
            expires = cast(int, payload['exp'])
        except KeyError:
            self._log.debug('No expiry in payload')
            raise AuthenticationError()

        if expires < time.time():
            self._log.debug('Message expired')
            raise AuthenticationError()

        return payload

import json
import os
from pathlib import Path
from typing import List, Mapping, NamedTuple, Optional, TypedDict


class Config(NamedTuple):
    """App configuration."""

    access_token_max_age: int
    aws_region: str
    aws_account_id: str
    counter_max: int
    counter_token_interval: int
    counter_token_ttl: int
    cors_ttl: int
    log_level: str
    login_page: str
    main_table: str
    otp_length: int
    public_key_url_base: str
    ses_login_sender: str
    session_cookie_name: str
    signing_key_name: str
    session_cookie_max_age: int
    session_id_bytes: int
    session_prefix: str
    subscription_prefix: str
    user_prefix: str
    website_origin: str


class CloudFrontParam(TypedDict):
    """CloudFront parameter values.

    .. _AWS docs:
        https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Parameter.html
    """

    ParameterKey: str
    ParameterValue: str


def _build_config(env: Mapping[str, str], params: List[CloudFrontParam]) \
        -> Config:
    """Build configuration object for the application.

    Args:
        env: A mapping object representing the string environment (os.environ).
        params: A list of Cloudfront parameters as expected by
            aws.templates.create-stack.
            .. _AWS docs:
                https://docs.aws.amazon.com/cli/latest/reference/cloudformation/create-stack.html#options

    Returns:
        The configuration object.

    """
    pdict = {p['ParameterKey']: p['ParameterValue'] for p in params}
    # These parameters are expected in the config, it should be an error if
    # they are missing from `pdict`.
    public_key_url_base = pdict['PublicKeyUrlBase']
    ses_login_sender = pdict['SESLoginSender']
    signing_key_name = pdict['SigningKeyAliasName']
    # Single quotes are necessary for CloudFormation template, but not in the
    # app
    site_origin = pdict['WebsiteOrigin'].replace('\'', '')

    # Ok for unit tests and functions that don't use it if there is no env var.
    # AWS Lambda default environment variables:
    aws_region = env.get('AWS_REGION', 'UnknownRegion')
    # Environment variables set Cloudformation template:
    aws_account_id = env.get('AWS_ACCOUNT_ID', 'UnknownAccountId')
    main_table = env.get('MAIN_TABLE_NAME', 'UnknownTableName')

    if env.get('TOX_TESTENV'):
        log_level = 'WARNING'
    else:
        log_level = pdict['LogLevel']

    return Config(
        access_token_max_age=(24 * 60 * 60),  # seconds
        aws_account_id=aws_account_id,
        aws_region=aws_region,
        counter_max=4,
        counter_token_interval=(24 * 60 * 60),  # seconds
        counter_token_ttl=(60 * 60),  # seconds
        cors_ttl=(10 * 60),  # seconds
        log_level=log_level,
        login_page='https://dokknet.com/login',
        main_table=main_table,
        otp_length=8,
        public_key_url_base=public_key_url_base,
        ses_login_sender=ses_login_sender,
        session_cookie_name='dokknet_session_token',
        session_id_bytes=32,
        session_cookie_max_age=(365 * 24 * 60 * 60),  # seconds
        session_prefix='SESS#',
        signing_key_name=signing_key_name,
        subscription_prefix='SUB#',
        user_prefix='USER#',
        website_origin=site_origin,
    )


_config: Optional[Config] = None


def _get_config() -> Config:
    """Lazy load config."""
    global _config
    if _config is None:
        target = os.environ.get('DEPLOYMENT_TARGET', 'dev')
        common_dir = Path(__file__).parent
        fname = f'configs/{target}.json'
        p = common_dir / fname
        with open(p) as f:
            _config = _build_config(os.environ, json.load(f))
    return _config


def __getattr__(name: str) -> Config:
    """Get a module level attribute.

    (New in Python 3.7.)
    """
    if name == 'config':
        return _get_config()
    else:
        raise AttributeError(f"module {__name__} has no attribute {name}")

"""Get parameters from AWS SSM.

Parameters are cached once loaded.
"""
import base64
from typing import Dict, Union

import boto3


_client = boto3.client('ssm')

_params: Dict[str, str] = {}
_params_dec: Dict[str, bytes] = {}


def get_param(name: str, b64decode: bool = False) -> Union[str, bytes]:
    """Get a parameter from AWS SSM.

    Parameters are cached once loaded.

    Args:
        name: The name of the parameter.
        b64decode: Whether to base64 decode the string. Returns bytes in this
            case.

    Returns:
        The parameter as a string or bytes if b64decode is True.

    Raises:
        botocore.exceptions.ClientError if the parameter can not be loaded
            from SSM.
        binascii.Error if b64decode is True and the parameter can not be
            decoded.

    """
    if name not in _params:
        res = _client.get_parameter(Name=name, WithDecryption=True)
        p = res['Parameter']['Value']
        _params[name] = p
    if b64decode and name not in _params_dec:
        _params_dec[name] = base64.b64decode(_params[name])

    if b64decode:
        return _params_dec[name]
    else:
        return _params[name]

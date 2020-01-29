#!/usr/bin/env python3
"""Create a signing key for the Auth service in AWS KMS."""
import argparse
import json
import logging
from typing import Dict, List

import boto3

import toml


def _get_from_config(configs: List[Dict[str, str]], key: str) -> str:
    try:
        value = next(el['ParameterValue'] for el in configs
                     if el['ParameterKey'] == key)
        return value
    except StopIteration:
        raise KeyError(f'Key {key} not found in configs')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('-t', '--target', type=str, required=True,
                    choices=('dev', 'staging', 'production'),
                    help='Deployment target')
args = parser.parse_args()

with open(f'app/common/configs/{args.target}.json') as f:
    configs = json.load(f)
with open('samconfig.toml') as f:
    sam_config = toml.load(f)

alias_name = _get_from_config(configs, 'SigningKeyAliasName')
policy_name = _get_from_config(configs, 'SigningKeyUsagePolicy')

kms_client = boto3.client('kms')
key_result = kms_client.create_key(
    KeyUsage='SIGN_VERIFY',
    CustomerMasterKeySpec='RSA_2048'
)
key_id = key_result['KeyMetadata']['KeyId']

region = sam_config['default']['deploy']['parameters']['region']
account_id = boto3.client('sts').get_caller_identity().get('Account')
policy_doc = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Sid': 'Stmt1578479818849',
            'Action': [
                'kms:DescribeKey',
                'kms:GetKeyPolicy',
                'kms:GetPublicKey',
                'kms:ListAliases',
                'kms:ListKeyPolicies',
                'kms:ListKeys',
                'kms:ListResourceTags',
                'kms:Sign',
                'kms:Verify'
            ],
            'Effect': 'Allow',
            'Resource': f'arn:aws:kms:{region}:{account_id}:key/{key_id}'
        }
    ]
}
iam_client = boto3.client('iam')
iam_client.create_policy(
    PolicyName=policy_name,
    PolicyDocument=json.dumps(policy_doc))


alias = f'alias/{alias_name}'
kms_client.create_alias(
    AliasName=alias,
    TargetKeyId=key_id
)
logging.info(f'Created signing key with alias:\n"{alias}""\nid: "{key_id}"'
             f'\niam policy: "{policy_name}')

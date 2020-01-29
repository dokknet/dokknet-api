#!/usr/bin/env python3
"""Setup custom domain for AWS API Gateway.

Run from repo root.

This script assumes that the `Auth` stack has been deployed and that the domain
was registered with AWS Route 53.

"""
import argparse
import logging
import subprocess

from deploy import build_and_deploy_service, get_stack_name, \
    param_overrides_to_str

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('-t', '--target', type=str, required=True,
                    choices=('dev', 'staging', 'production'),
                    help='Deployment target')
parser.add_argument('-d', '--domain', type=str, required=True,
                    help='Domain name')
parser.add_argument('-z', '--zone_id', type=str, required=True,
                    help='Hosted zone id')
args = parser.parse_args()

cmd = ['aws', 'cloudformation', 'deploy',
       '--capabilities', 'CAPABILITY_IAM',
       '--stack-name', 'cfn-certificate-provider',
       '--template-file', 'cloudformation/provider/cfn-certificate-provider.yml',  # noqa 501
       '--no-fail-on-empty-changeset']  # noqa 501
subprocess.run(cmd, check=True)

params = [
    {
        'ParameterKey': 'DeploymentTarget',
        'ParameterValue': args.target
    },
    {
        'ParameterKey': 'Domain',
        'ParameterValue': args.domain
    },
    {
        'ParameterKey': 'HostedZoneId',
        'ParameterValue': args.zone_id
    }
]
logging.info('Setting up domain. This will take a while...')
param_overrides = param_overrides_to_str(params)
cmd = ['aws', 'cloudformation', 'deploy',
       '--capabilities', 'CAPABILITY_IAM',
       '--stack-name', get_stack_name('domain', args.target),
       '--template-file', 'cloudformation/domain.yml',
       '--no-fail-on-empty-changeset',
       '--parameter-overrides', *param_overrides.split(' ')]
subprocess.run(cmd, check=True)
build_and_deploy_service('domain', args.target)
logging.info('Success')

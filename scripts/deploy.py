#!/usr/bin/env python3
"""Build and deploy Cloudformation stacks with AWS SAM.

Run from repo root.

"""
import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, List

from samcli.lib.bootstrap import bootstrap

import toml


_IGNORE_BINARY = shutil.ignore_patterns('__pycache__',
                                        '*.py[cod]',
                                        '*$py.class',
                                        '*.so')
# Order of fresh deployments
_SERVICE_ORDER = ('database', 'cognito', 'auth')


def build_and_deploy_service(service_name: str, deployment_target: str) \
        -> None:
    build_service(service_name)
    param_overrides = get_param_overrides(deployment_target)
    deploy_service(service_name, deployment_target, param_overrides)


def build_service(service_name: str) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy files that we want included in the deployment artifact in a
        # temporary directory.
        app_dir = tmpdir + '/app'
        shutil.copytree('app', app_dir, ignore=_IGNORE_BINARY)
        shutil.copy('LICENSE', app_dir)

        deployment_template = build_template(service_name, app_dir)

        # Sam creates the deployment artifact from the source in the temporary
        # directory and puts it into the default directory from which
        # `sam deploy` can deploy it.
        sam_build = ['sam', 'build',
                     '--template', deployment_template,
                     '--manifest', 'requirements/requirements.txt',
                     '--base-dir', tmpdir]
        subprocess.run(sam_build, check=True)


def build_template(service_name: str, app_dir: str) -> str:
    template = f'cloudformation/{service_name}.yml'
    dep_template = f'{app_dir}/template.yml'
    with open(template, 'r') as infile:
        intext = infile.read()

    dep_id = get_deployment_id()
    outtext = intext.replace('$DEPLOYMENT_ID$', dep_id)
    with open(dep_template, 'w') as outfile:
        outfile.write(outtext)

    return dep_template


def deploy_service(service_name: str, deployment_target: str,
                   param_overrides: str = '') -> None:
    sam_config = load_sam_config()
    try:
        s3_bucket = get_sam_param(sam_config, deployment_target, 's3_bucket')
    except KeyError:
        s3_bucket = setup_deployment_bucket(sam_config, deployment_target)

    stack_name = get_stack_name(service_name, deployment_target)
    cmd = ['sam', 'deploy',
           '--no-fail-on-empty-changeset',
           '--stack-name', stack_name,
           '--s3-bucket', s3_bucket]
    if param_overrides:
        cmd.extend(['--parameter-overrides', param_overrides])
    subprocess.run(cmd, check=True)


def get_deployment_id() -> str:
    timestamp = round(time.time() * 1000)
    # must be alphanumeric
    return str(timestamp)


def load_sam_config():
    with open('samconfig.toml') as f:
        return toml.load(f)


def get_sam_param(sam_config, target: str, param: str) -> str:
    return sam_config[target]['deploy']['parameters'][param]


def set_sam_param(sam_config, target: str, param: str, val: str) -> None:
    if target not in sam_config:
        sam_config[target] = {
            'deploy': {
                'parameters': {}
            }
        }
    sam_config[target]['deploy']['parameters'][param] = val


def get_param_overrides(deployment_target: str) -> str:
    params_path = f'app/common/configs/{deployment_target}.json'
    with open(params_path) as f:
        param_overrides = json.load(f)
    return param_overrides_to_str(param_overrides)


def get_stack_name(service_name: str, deployment_target: str) -> str:
    service_cap = service_name.capitalize()
    target_cap = deployment_target.capitalize()
    stack_name = f'{service_cap}Service-{target_cap}'
    return stack_name


def param_overrides_to_str(param_overrides: List[Dict[str, str]]) -> str:
    # sam deploy doesn't support passing JSON, all params must be passed
    # as a single string
    params = ['{}={}'.format(p["ParameterKey"], p["ParameterValue"])
              for p in param_overrides]
    param_overrides = ' '.join(params)
    return param_overrides


def setup_deployment_bucket(sam_config, deployment_target) -> str:
    region = get_sam_param(sam_config, 'default', 'region')
    # Gets AWS profile from ambient configuration.
    s3_bucket = bootstrap.manage_stack(profile=None, region=region)
    set_sam_param(sam_config, deployment_target, 's3_bucket', s3_bucket)
    write_sam_config(sam_config)
    logging.info(f'Updated `samconfig.toml` with deployment S3 bucket for '
                 f'target {args.target}. You can commit the updated config '
                 f'file.')
    return s3_bucket


def write_sam_config(sam_config):
    with open('samconfig.toml', 'w') as f:
        toml.dump(sam_config, f)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-t', '--target', type=str, required=True,
                        choices=('dev', 'staging', 'production'),
                        help='Deployment target')
    parser.add_argument('-n', '--service_name', type=str,
                        choices=_SERVICE_ORDER,
                        help='Service name')
    parser.add_argument('--deploy_all', action='store_true',
                        help='Deploy all services')
    args = parser.parse_args()

    if args.deploy_all:
        services = _SERVICE_ORDER
    elif args.service_name:
        services = [args.service_name]
    else:
        logging.error('One of --service_name or --deploy_all must be '
                      'specified')
        sys.exit(1)

    for name in services:
        build_and_deploy_service(name, args.target)
    for name in services:
        s_name = get_stack_name(name, args.target)
        logging.info(f'+++ Successfully deployed {s_name} +++')

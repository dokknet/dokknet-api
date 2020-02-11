#!/usr/bin/env python3
"""Delete a CloudFormation stack.

Useful for development (and doesn't support other deployment targets).

Run from repo root.

"""
import argparse
import logging

import boto3

from deploy import get_stack_name


def delete_stack(stack_name):
    logging.info(f'Deleting stack {stack_name}...')
    client = boto3.client('cloudformation')
    client.delete_stack(StackName=stack_name)
    waiter = client.get_waiter('stack_delete_complete')
    waiter.wait(
        StackName=stack_name,
        WaiterConfig={
            'Delay': 5  # seconds
        }
    )
    logging.info(f'Successfully deleted stack {stack_name}')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-n', '--service_name', type=str,
                        required=True,
                        help='Service name')
    args = parser.parse_args()

    stack_name = get_stack_name(service_name=args.service_name,
                                deployment_target='dev')
    delete_stack(stack_name)

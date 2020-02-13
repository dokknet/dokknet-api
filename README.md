# Dokknet API

Status: Prototype

The Dokknet API provides authentication, authorization and subscription management services through a REST API (sub management is not implemented yet).


## Development

### Prerequisites

1. Install the [Miniconda]('https://docs.conda.io/en/latest/miniconda.html') Python virtual environment manager.
1. Create development environment and install dependencies with: `conda env create -f environment.yml` (from the repo root).
1. Activate virtual environment: `conda activate dokknet_api`

### Dependencies

Dependencies are specified in `requirements/*.in` files down to minor versions which are  then pinned with the `./scripts/pip_compile.py` command that outputs `requirements/*.txt` files that can be fed to `pip -r`.

There are three levels of dependencies:

1. production
1. test
1. dev

Dev dependencies include all tools for development and test dependencies include packages needed to run unit tests. 
Production dependencies are needed to execute the handlers in the Lambda environment. 
Test dependencies include production dependencies.
Boto3 is included in the Lambda runtime [(docs)](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html), so it's only included as a test dependency.

### Testing

Run tests from the repo root with: `tox`. This will automatically install test dependencies in a separate virtual environment.

Run unit tests only: `tox -e py38`

Run type checks only: `tox -e mypy`

Run Cloudformation linters: `tox -e cfn_lint`

Run all linters: `tox -e linters`

Try to fix style errors automatically: `tox -e autopep8`

## Deployment

### Prerequisites

1. Development prerequisites
1. An AWS organization with separate accounts for development, staging and 
production environments. (Note that if you're only interested in a development
deployment, all you need is a single AWS account.)

### Credentials

All deployment commands take AWS credentials either from environment variables or local configuration files (ambient configuration). 

For development, configure local AWS credentials following the 
[Quickly Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration) guide.

Production and staging credentials should never be stored on developer machines. 
By default, these credentials would be injected as environment variables in a secure CD pipeline for the deployment scripts, but if you have to run production or staging deployments locally, you can also supply these credentials with the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables. If you do this, make sure that these environment variables are not recorded in your shell history.

TODO (abiro) create IAM deployment role.

### Deployment Targets

1. `production`: https://dokknet-api.com/v1
1. `staging`: TODO (abiro)
1. `dev`: Random AWS API gateway subdomain of the format `https://{api-id}.execute-api.{region}.amazonaws.com/{stage}`

### Before first deployment

Before the first deployment for a target, the following one-time tasks need to be completed:

1. Create signing key for the API by running 
`./scripts/create_signing_key -t {deployment_target}` 
from the repo root. This is necessary, because CloudFormation doesn't support provisioning asymmetric signing keys. ([issue](https://github.com/aws-cloudformation/aws-cloudformation-coverage-roadmap/issues/337))

### Deploy

Run 
`./scripts/deploy.py -t {deployment_target} --deploy_all` 
from the repo root to deploy all services or 
`./scripts/deploy.py -t {deployment_target} -n {service_name}` 
to deploy a specific service. For example, to provision a dev database, run 
`./scripts/deploy.py -t dev -n database`.


### After first deployment

After the first deployment for a target, the following one-time tasks need to be completed:

1. Set up a custom domain for AWS API gateway. See instructions in [AWS docs.](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html) (We only set up domains for `production` and `staging` so you can ignore this step if you only want a `dev` deployment.)
1. Validate email address with AWS Simple Email Service (SES) to send login links. See instructions in the [Email Setup](#email-setup) section.

#### Email Setup

##### For development:

1. Follow the instructions in [Verifying an Email Address with AWS SES](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses-procedure.html) for the email address you want to use to send log in emails from. You will be only able to send login emails to verified emails, so if you want to send emails to addresses other than your sender, you need to verify those as well.

##### For production/staging:

1. Follow the instructions in [Verifying a Domain With Amazon SES](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-domain-procedure.html) for the domain that you want to send login emails from. 
1. Follow the instructions in [Moving Out of the Amazon SES Sandbox](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html) to let you send emails to arbitrary addresses. Note that this might take up to 24 hours, but the lower limits you request, the faster it will be resolved.

Finally, change the `SESLoginSender` value in `app/common/configs/{deployment_target}.json` to your email address. (Make sure to deploy the `cognito` service with
`./sripts/deploy.py -t {deployment_target} -n cognito`
to make the config changes take effect.)


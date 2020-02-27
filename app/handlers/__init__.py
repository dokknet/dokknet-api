"""AWS Lambda event handlers of the application.

Each top level package in `app.handlers` corresponds to a CloudFormation stack.
Each stack defines a service of the application.

Handlers may import names from peer modules or common modules, but may not
import from other handler packages. Eg.: `app.handlers.auth.session_cookie` may
import from `app.common.token` or `app.handlers.auth.access_token`, but it may
not import from `app.handlers.cognito`.

"""

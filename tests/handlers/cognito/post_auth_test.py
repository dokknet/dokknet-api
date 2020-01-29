from typing import Tuple, cast
from unittest.mock import MagicMock

import app.handlers.cognito.post_auth as m
from app.common.types.cognito import PostAuthEvent
from app.common.types.lambd import LambdaContext

from tests import TestBase


class TestPostAuth(TestBase):
    _to_patch = [
        'app.handlers.cognito.post_auth._cognito_client'
    ]

    def _get_args(self, verified: str) -> Tuple[PostAuthEvent, LambdaContext]:
        event = cast(PostAuthEvent, self.get_event('post-auth'))
        attributes = event['request']['userAttributes']
        attributes['email_verified'] = verified
        context = MagicMock()
        return event, context

    def test_noop_for_verified(self):
        cognito_client = self._mocks['_cognito_client']
        event, context = self._get_args(verified='true')
        res = m.handler(event, context)
        self.assertIs(res, event)
        self.assertEqual(len(res['response']), 0)
        cognito_client.admin_update_user_attributes.assert_not_called()

    def test_sets_verified(self):
        cognito_client = self._mocks['_cognito_client']
        event, context = self._get_args(verified='false')
        userattrs = event['request']['userAttributes']
        user_pool_id = event['userPoolId']
        res = m.handler(event, context)
        self.assertIs(res, event)
        self.assertEqual(len(res['response']), 0)
        cognito_client.admin_update_user_attributes.assert_called_once_with(
            UserPoolId=user_pool_id,
            Username=userattrs['sub'],
            UserAttributes=[{'Name': 'email_verified', 'Value': 'true'}]
        )

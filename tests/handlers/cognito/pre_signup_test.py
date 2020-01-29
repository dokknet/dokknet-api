from typing import cast
from unittest.mock import MagicMock

import app.handlers.cognito.pre_signup as m
from app.common.types.cognito import PreSignUpEvent

from tests import TestBase


class TestPreSignUpHandler(TestBase):
    def test_response(self):
        context = MagicMock()
        event = cast(PreSignUpEvent, self.get_event('pre-sign-up'))
        res = m.handler(event, context)

        # Handler must return the event object
        self.assertIs(event, res)
        self.assertTrue(event['response']['autoConfirmUser'])
        self.assertFalse(event['response']['autoVerifyEmail'])

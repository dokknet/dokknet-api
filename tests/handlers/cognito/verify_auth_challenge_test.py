from typing import Tuple, cast
from unittest.mock import MagicMock

import app.handlers.cognito.verify_auth_challenge as m
from app.common.types.cognito import VerifyAuthChallengeEvent
from app.common.types.lambd import LambdaContext

from tests import TestBase


class TestVerifyAuthChallenge(TestBase):
    def _get_args(self, otp: str, answer: str) \
            -> Tuple[VerifyAuthChallengeEvent, LambdaContext]:
        event = cast(VerifyAuthChallengeEvent,
                     self.get_event('verify-auth-challenge'))
        request = event['request']
        request['privateChallengeParameters']['otp'] = otp
        request['challengeAnswer'] = answer
        context = MagicMock()
        return event, context

    def test_correct_answer(self):
        otp = 'abcd-4321'
        answer = otp
        event, context = self._get_args(otp=otp, answer=answer)
        res = m.handler(event, context)
        self.assertIs(res, event)
        response = res['response']
        self.assertTrue(response['answerCorrect'])

    def test_wrong_answer(self):
        otp = 'abcd-1234'
        answer = 'fooo-barr'
        event, context = self._get_args(otp=otp, answer=answer)
        res = m.handler(event, context)
        self.assertIs(res, event)
        response = res['response']
        self.assertFalse(response['answerCorrect'])

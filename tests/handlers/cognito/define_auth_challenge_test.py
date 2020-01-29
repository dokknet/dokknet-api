from copy import deepcopy
from typing import Optional, Tuple, cast
from unittest.mock import MagicMock

import app.handlers.cognito.define_auth_challenge as m
from app.common.types.cognito import DefineAuthChallengeEvent
from app.common.types.lambd import LambdaContext

from tests import TestBase


class TestDefineAuthChallenge(TestBase):
    def _get_args(self, challenge_res: bool) \
            -> Tuple[DefineAuthChallengeEvent, LambdaContext]:
        event = cast(DefineAuthChallengeEvent,
                     self.get_event('define-auth-challenge'))
        context = MagicMock()
        req = event['request']
        session = req['session']
        session[-1]['challengeResult'] = challenge_res
        return event, context

    def _run_test(self, event: DefineAuthChallengeEvent,
                  context: LambdaContext, issue_tokens: bool,
                  fail_auth: bool, challenge_name: Optional[str]):
        result = m.handler(event, context)
        self.assertIs(event, result)
        response = result['response']
        self.assertEqual(response['issueTokens'], issue_tokens)
        self.assertEqual(response['failAuthentication'], fail_auth)
        if challenge_name is None:
            self.assertNotIn('challengeName', response)
        else:
            self.assertEqual(response['challengeName'], challenge_name)

    def test_reject_first(self):
        """Invalid otp on first authentication attempt."""
        event, context = self._get_args(challenge_res=False)
        self._run_test(event, context, issue_tokens=False, fail_auth=False,
                       challenge_name='CUSTOM_CHALLENGE')

    def test_reject_second(self):
        event, context = self._get_args(challenge_res=False)
        session = event['request']['session']
        session.append(deepcopy(session[-1]))
        self._run_test(event, context, issue_tokens=False, fail_auth=False,
                       challenge_name='CUSTOM_CHALLENGE')

    def test_fail_third(self):
        event, context = self._get_args(challenge_res=False)
        session = event['request']['session']
        session.append(deepcopy(session[-1]))
        session.append(deepcopy(session[-1]))
        self._run_test(event, context, issue_tokens=False, fail_auth=True,
                       challenge_name=None)

    def test_allow_empty(self):
        """No previous authentication attempt."""
        event, context = self._get_args(challenge_res=True)
        event['request']['session'] = []
        self._run_test(event, context, issue_tokens=False, fail_auth=False,
                       challenge_name='CUSTOM_CHALLENGE')

    def test_allow_first(self):
        """Valid code on first authentication attempt."""
        event, context = self._get_args(challenge_res=True)
        self._run_test(event, context, issue_tokens=True, fail_auth=False,
                       challenge_name=None)

    def test_allow_second(self):
        event, context = self._get_args(challenge_res=False)
        session = event['request']['session']
        session.append(deepcopy(session[-1]))
        session[-1]['challengeResult'] = True
        self._run_test(event, context, issue_tokens=True, fail_auth=False,
                       challenge_name=None)

    def test_allow_third(self):
        event, context = self._get_args(challenge_res=False)
        session = event['request']['session']
        session.append(deepcopy(session[-1]))
        session.append(deepcopy(session[-1]))
        session[-1]['challengeResult'] = True
        self._run_test(event, context, issue_tokens=True, fail_auth=False,
                       challenge_name=None)

from unittest import TestCase

from tests import TestBase


class TestBaseTest(TestCase):
    def test_get_event(self):
        tb = TestBase()
        event = tb.get_event('pre-sign-up')
        self.assertIsInstance(event, dict)

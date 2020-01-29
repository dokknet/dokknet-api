from unittest.mock import MagicMock, patch

import app.common.config as m

from tests import TestBase


class TestBuildConfig(TestBase):
    def test_session_table_name(self):
        configs = self.get_configs('dev')
        table_name = 'TestTableName'
        env = {'MAIN_TABLE_NAME': table_name}
        conf = m._build_config(env, configs)
        self.assertEqual(conf.main_table, table_name)

    def test_ses_login_sender(self):
        configs = self.get_configs('dev')
        sender = 'unittest_sender@example.com'
        sender_d = next(d for d in configs
                        if d['ParameterKey'] == 'SESLoginSender')
        sender_d['ParameterValue'] = sender
        conf = m._build_config({}, configs)
        self.assertEqual(conf.ses_login_sender, sender)


class TestConfig(TestBase):

    @patch('app.common.config._build_config')
    @patch('app.common.config.os')
    def test_uses_env(self, os_mock, build_config_mock):
        # TODO (abiro) refactor
        environ_mock = MagicMock()
        os_mock.environ = environ_mock
        environ_mock.get.return_value = 'dev'
        m._config = None
        m._get_config()
        build_config_mock.assert_called_once()
        self.assertIs(build_config_mock.call_args.args[0], environ_mock)

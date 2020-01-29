import base64

import app.common.params as m

from tests import TestBase


class TestGetParam(TestBase):
    _to_patch = [
        'app.common.params._client'
    ]

    def setUp(self):
        super().setUp()
        m._params = {}
        m._params_dec = {}

    def test_correct_args(self):
        client = self._mocks['_client']

        name = 'my-name'
        value = 'my-value'
        ret_value = {'Parameter': {'Value': value}}
        client.get_parameter.return_value = ret_value
        res = m.get_param(name)
        client.get_parameter.assert_called_once_with(Name=name,
                                                     WithDecryption=True)
        self.assertEqual(res, value)

    def test_b64decode(self):
        client = self._mocks['_client']

        name = 'my-name'
        value = base64.b64encode(b'my-value')
        ret_value = {'Parameter': {'Value': value}}
        client.get_parameter.return_value = ret_value
        res = m.get_param(name, b64decode=True)
        self.assertEqual(res, b'my-value')

from unittest.mock import patch

import app.common.db.op_args as m
from app.common import db

from tests import TestBase


class OpTestMixin:
    def setUp(self):
        self._pk = db.PartitionKey('User', 'eva.lu-ator@example.com')
        self._sk = db.SortKey('Subscription', 'mitpress.mit.edu')
        self._table_name = 'my-table'

    def test_table_name(self):
        kwargs = self._op_arg.get_kwargs(self._table_name)
        self.assertEqual(kwargs['TableName'], self._table_name)


class TestOpArg(TestBase):
    def test_bool_conversion(self):
        res = m.PutArg._get_dynamo_val(False)
        exp = {'BOOL': False}
        self.assertDictEqual(exp, res)

    def test_int_conversion(self):
        res = m.PutArg._get_dynamo_val(-1)
        exp = {'N': '-1'}
        self.assertDictEqual(exp, res)

    def test_float_conversion(self):
        res = m.PutArg._get_dynamo_val(1 / 3)
        exp = {'N': str(1 / 3)}
        self.assertDictEqual(exp, res)

    def test_str_conversion(self):
        res = m.PutArg._get_dynamo_val('32foo')
        exp = {'S': '32foo'}
        self.assertDictEqual(exp, res)


class TestPutArg(OpTestMixin, TestBase):
    def setUp(self):
        super().setUp()
        self._op_arg = m.PutArg(self._pk, self._sk)

    @patch('app.common.db.op_args.datetime')
    def test_correct_timestamp(self, datetime):
        utc_now = 'utc-now'
        datetime.utcnow.return_value = utc_now
        self.assertEqual(m.PutArg._get_updated_at(), utc_now)

    @patch('app.common.db.op_args.PutArg._get_updated_at')
    def test_adds_update_at(self, get_update_at):
        exp_update_at = 'test-time-stamp'
        get_update_at.return_value = exp_update_at
        item = self._op_arg._get_dynamo_item()
        self.assertEqual(item['UpdatedAt']['S'], exp_update_at)

    def test_keys_added(self):
        item = self._op_arg._get_dynamo_item()
        self.assertEqual(item['PK']['S'], self._pk)
        self.assertEqual(item['SK']['S'], self._sk)

    def test_adds_attributes(self):
        put_arg = m.PutArg(self._pk, self._sk,
                           attributes={'foo': '1', 'bar': 2})
        item = put_arg._get_dynamo_item()
        self.assertEqual(item['foo']['S'], '1')
        self.assertEqual(item['bar']['N'], '2')

    def test_attributes_dont_overwrite_keys(self):
        attributes = {
            'foo': '1',
            'bar': 2,
            'PK': 'my-pk',
            'SK': 'my-sk'
        }
        put_arg = m.PutArg(self._pk, self._sk, attributes=attributes)
        item = put_arg._get_dynamo_item()
        self.assertEqual(item['PK']['S'], self._pk)
        self.assertEqual(item['SK']['S'], self._sk)

    def test_disallow_overwrite(self):
        put_arg = m.PutArg(self._pk, self._sk, allow_overwrite=False)
        kwargs = put_arg.get_kwargs('my-table')
        cond_expression = 'attribute_not_exists(PK)'
        self.assertEqual(kwargs['ConditionExpression'], cond_expression)

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Put')


class TestInsertArg(OpTestMixin, TestBase):
    def setUp(self):
        super().setUp()
        self._op_arg = m.InsertArg(self._pk, self._sk)

    def test_no_overwrite(self):
        kwargs = self._op_arg.get_kwargs('my-table')
        cond_expression = 'attribute_not_exists(PK)'
        self.assertEqual(kwargs['ConditionExpression'], cond_expression)

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Put')


class TestDeleteArg(OpTestMixin, TestBase):
    def setUp(self):
        super().setUp()
        self._op_arg = m.DeleteArg(self._pk, self._sk)

    def test_key(self):
        kwargs = self._op_arg.get_kwargs('')
        key = kwargs['Key']
        self.assertEqual(key['PK']['S'], str(self._pk))
        self.assertEqual(key['SK']['S'], str(self._sk))

    def test_not_idempotent(self):
        kwargs = self._op_arg.get_kwargs('')
        self.assertEqual(kwargs['ConditionExpression'],
                         'attribute_exists(PK)')

    def test_idempotent(self):
        op_arg = m.DeleteArg(self._pk, self._sk, idempotent=True)
        kwargs = op_arg.get_kwargs('')
        self.assertNotIn('ConditionExpression', kwargs)

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Delete')

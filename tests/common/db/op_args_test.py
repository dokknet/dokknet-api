import re
from unittest.mock import patch

import boto3.dynamodb.conditions as cond

import app.common.db.op_args as m
from app.common import db

from tests import TestBase


class User(db.EntityName):
    pass


class Subscription(db.EntityName):
    pass


class TestOpArg(TestBase):
    def test_iso_now(self):
        res = m.OpArg._iso_now()
        iso_format = r'\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}'
        self.assertTrue(re.match(iso_format, res))


class OpTestMixin:
    def setUp(self):
        self._pk = db.PartitionKey(User, 'eva.lu-ator@example.com')
        self._sk = db.SortKey(Subscription, 'mitpress.mit.edu')
        self._table_name = 'my-table'

    def test_table_name(self):
        kwargs = self._op_arg.get_kwargs(self._table_name)
        self.assertEqual(kwargs['TableName'], self._table_name)


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
        op_arg = m.DeleteArg(self._pk, self._sk, idempotent=False)
        kwargs = op_arg.get_kwargs('')
        self.assertEqual(kwargs['ConditionExpression'],
                         'attribute_exists(PK)')

    def test_idempotent(self):
        kwargs = self._op_arg.get_kwargs('')
        self.assertNotIn('ConditionExpression', kwargs)

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Delete')

    def test_serialize_dict(self):
        d = {
            'foo': False,
            'bar': 1
        }
        res = self._op_arg._serialize_dict(d)
        exp = {
            'foo': {'BOOL': False},
            'bar': {'N': '1'}
        }
        self.assertDictEqual(res, exp)


class TestPutArg(OpTestMixin, TestBase):
    def setUp(self):
        super().setUp()
        self._op_arg = m.PutArg(self._pk, self._sk)

    @patch('app.common.db.op_args.PutArg._iso_now')
    def test_adds_created_at(self, iso_now):
        exp_created_at = 'test-time-stamp'
        iso_now.return_value = exp_created_at
        item = self._op_arg._get_dynamo_item()
        self.assertEqual(item['CreatedAt']['S'], exp_created_at)

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


class TestQueryArg(TestBase):
    def setUp(self):
        super().setUp()
        self._pk = db.PartitionKey(User, 'eva.lu-ator@example.com')
        self._sk = db.SortKey(Subscription, 'mitpress.mit.edu')
        self._cond = cond.Key('PK').eq(str(self._pk))
        self._op_arg = m.QueryArg(self._cond)

    def test_key_cond(self):
        kwargs = self._op_arg.get_kwargs('')
        key_cond = kwargs['KeyConditionExpression']
        self.assertEqual(self._cond, key_cond)

    def test_limit(self):
        kwargs = self._op_arg.get_kwargs('')
        limit = kwargs['Limit']
        self.assertLessEqual(limit, 1000)

    def test_over_limit(self):
        with self.assertRaises(ValueError):
            m.QueryArg(self._cond, limit=10000)

    def test_default_projection(self):
        kwargs = self._op_arg.get_kwargs('')
        proj = kwargs['ProjectionExpression']
        self.assertLessEqual(proj, 'SK')

    def test_projection(self):
        op_arg = m.QueryArg(self._cond, attributes=['PK', 'SK', 'foo'])
        kwargs = op_arg.get_kwargs('')
        proj = kwargs['ProjectionExpression']
        self.assertLessEqual(proj, 'PK,SK,foo')

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Query')


class TestUpdateArg(OpTestMixin, TestBase):
    def setUp(self):
        super().setUp()
        self._op_arg = m.UpdateArg(self._pk, self._sk)

    def test_key(self):
        kwargs = self._op_arg.get_kwargs('')
        key = kwargs['Key']
        self.assertEqual(key['PK']['S'], str(self._pk))
        self.assertEqual(key['SK']['S'], str(self._sk))

    def test_put_args(self):
        put_attrs = {'foo': 1}
        op_arg = m.UpdateArg(self._pk, self._sk, put_attributes=put_attrs)
        kwargs = op_arg.get_kwargs('')
        foo_update = kwargs['AttributeUpdates']['foo']
        self.assertEqual(foo_update['Action'], 'PUT')
        self.assertEqual(foo_update['Value']['N'], str(put_attrs['foo']))

    def test_op_name(self):
        self.assertEqual(self._op_arg.op_name, 'Update')

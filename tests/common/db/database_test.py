import hashlib
from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

from boto3.dynamodb.conditions import Key

from botocore.exceptions import ClientError

from app.common import db
from app.common.db.database import Database

from tests import TestBase


class TestRemovePrefix(TestBase):
    def test_correct_suffix(self):
        prefix = 'foo'
        suffix = 'bar'
        string = prefix + suffix
        self.assertEqual(Database._remove_prefix(prefix, string), suffix)

    def test_raise_invalid_prefix(self):
        prefix = 'foo'
        string = 'fubar'
        with self.assertRaises(ValueError):
            Database._remove_prefix(prefix, string)


class TestHexHash(TestBase):
    def test_correct_algorithm(self):
        sid = b'unit-test-session-id'
        res = Database.hex_hash(sid)
        alg = hashlib.sha3_256()
        alg.update(sid)
        self.assertEqual(res, alg.hexdigest())


class TestStripPrefixes(TestBase):
    def setUp(self):
        self._pk = db.PartitionKey('User', 'foo@example.com')
        self._sk = db.SortKey('Domain', 'docs.example.com')

    def test_noop_on_no_keys(self):
        item = {
            'foo': 'bar'
        }
        res = Database._strip_prefixes(self._pk, self._sk, item)
        self.assertDictEqual(item, res)

    def test_strips_prefixes(self):
        item = {
            'PK': str(self._pk),
            'SK': str(self._sk)
        }
        res = Database._strip_prefixes(self._pk, self._sk, item)
        self.assertEqual(res['PK'], self._pk.value)
        self.assertEqual(res['SK'], self._sk.value)

    def test_handles_single_entity(self):
        sk = db.SingleSortKey('Subscription')
        item = {
            'PK': str(self._pk),
            'SK': str(sk)
        }
        res = Database._strip_prefixes(self._pk, sk, item)
        self.assertEqual(res['PK'], self._pk.value)
        self.assertEqual(res['SK'], '')

    def test_makes_copy(self):
        item = {
            'PK': str(self._pk),
            'SK': str(self._sk)
        }
        res = Database._strip_prefixes(self._pk, self._sk, item)
        self.assertNotEqual(item['PK'], res['PK'])
        self.assertNotEqual(item['SK'], res['SK'])


class TestInit(TestBase):
    _to_patch = [
        'app.common.db.database.boto3'
    ]

    def test_client(self):
        boto3 = self._mocks['boto3']

        db = Database('my-table')
        self.assertEqual(db._client, boto3.client.return_value)

    def test_table(self):
        boto3 = self._mocks['boto3']
        resource = MagicMock()
        boto3.resource.return_value = resource
        table_name = 'my-table'
        database = Database(table_name)
        resource.Table.assert_called_once_with(table_name)
        self.assertEqual(database._table, resource.Table.return_value)


class DatabaseTestCase(TestBase):
    _to_patch = [
        'app.common.db.database.boto3',
        'app.common.db.database.logging',
        'app.common.db.database.Database._table#PROPERTY',
        'app.common.db.database.Database._client#PROPERTY'
    ]

    def setUp(self):
        super().setUp()

        self._table = MagicMock()
        self._mocks['_table'].return_value = self._table
        self._client = MagicMock()
        self._mocks['_client'].return_value = self._client
        self._pk = db.PartitionKey('User', 'foo@example.com')
        self._sk = db.SortKey('Subscription', 'docs.example.com')


class PutItemTestMixin(ABC):
    @abstractmethod
    def _call_test_fn(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _dynamo_method(self):
        raise NotImplementedError

    def test_handles_conditional_check_failed(self):
        error_response = {'Error': {'Code': 'ConditionalCheckFailedException'}}
        self._dynamo_method.side_effect = db.ClientError(error_response,
                                                         'PutItem')
        with self.assertRaises(db.ItemExistsError):
            self._call_test_fn()

    def test_raises_client_error(self):
        self._dynamo_method.side_effect = db.ClientError({},
                                                         'PutItem')
        with self.assertRaises(db.ClientError):
            self._call_test_fn()


class QueryTestMixin(ABC):
    @abstractmethod
    def _call_test_fn(self, index_name=None):
        raise NotImplementedError

    def _test_correct_key(self, exp_cond):
        self._call_test_fn()
        key_cond = self._table.query.call_args.kwargs['KeyConditionExpression']
        self.assertEqual(key_cond, exp_cond)

    def test_handles_no_result(self):
        self._table.query.return_value = {}
        self.assertFalse(self._call_test_fn())

    def test_handles_empty_result(self):
        self._table.query.return_value = {'Items': []}
        self.assertFalse(self._call_test_fn())

    def test_correct_index(self):
        exp_index_name = 'my-index'
        self._call_test_fn(index_name=exp_index_name)
        index_name = self._table.query.call_args.kwargs['IndexName']
        self.assertEqual(exp_index_name, index_name)


class TestFetch(DatabaseTestCase, QueryTestMixin):
    def _call_test_fn(self, index_name=None, attributes=None):
        database = Database('my-table')
        return database.fetch(self._pk, self._sk, index_name=index_name,
                              attributes=attributes)

    def test_correct_key(self):
        pk_cond = Key('PK').eq(str(self._pk))
        sk_cond = Key('SK').begins_with(str(self._sk))
        self._test_correct_key(pk_cond & sk_cond)

    def test_default_attributes(self):
        self._call_test_fn()
        attributes = self._table.query.call_args.kwargs['AttributesToGet']
        self.assertListEqual(attributes, ['PK', 'SK'])

    def test_attributes_to_get(self):
        exp_attributes = ['foo', 'bar']
        self._call_test_fn(attributes=exp_attributes)
        attributes = self._table.query.call_args.kwargs['AttributesToGet']
        self.assertListEqual(attributes, exp_attributes)

    def test_strips_prefixes(self):
        item = {'PK': str(self._pk), 'SK': str(self._sk)}
        self._table.query.return_value = {'Items': [item]}
        res = self._call_test_fn()
        self.assertEqual(res['PK'], self._pk.value)
        self.assertEqual(res['SK'], self._sk.value)

    def test_raises_too_many_results(self):
        self._table.query.return_value = {'Items': [{}, {}]}
        with self.assertRaises(db.TooManyResultsError):
            self._call_test_fn()


class TestInsert(DatabaseTestCase, PutItemTestMixin):
    def _call_test_fn(self, attributes=None, table_name='my-table'):
        database = Database(table_name)
        return database.insert(self._pk, self._sk, attributes=attributes)

    @property
    def _dynamo_method(self):
        return self._client.put_item

    @patch('app.common.db.database.InsertArg', autospec=True)
    def test_converts_to_insert_arg(self, insert_arg_cls):
        get_kwargs = insert_arg_cls.return_value.get_kwargs
        attributes = {'foo': 1, 'bar': '2'}
        table_name = 'foo-table'

        kwargs = {'Arg1': 'Value1', 'Arg2': 'Value2'}
        get_kwargs.return_value = kwargs

        self._call_test_fn(attributes=attributes, table_name=table_name)

        insert_arg_cls.assert_called_once_with(self._pk, self._sk,
                                               attributes=attributes)
        get_kwargs.assert_called_once_with(table_name)
        self._client.put_item.assert_called_once_with(**kwargs)


class TestTransactWriteItems(DatabaseTestCase, PutItemTestMixin):

    def _call_test_fn(self, items=None, table_name='my-table'):
        database = Database(table_name)
        if not items:
            items = []
        return database.transact_write_items(items)

    @property
    def _dynamo_method(self):
        return self._client.transact_write_items

    def test_converts_to_op_name_dicts(self):
        op_name = 'my-op-name'
        table_name = 'foo-table-name'

        arg_mock = MagicMock(spec=db.PutArg)
        arg_mock.get_kwargs.return_value = 1
        arg_mock.op_name = op_name
        expected_item = {op_name: 1}

        self._call_test_fn(items=[arg_mock], table_name=table_name)
        arg_mock.get_kwargs.assert_called_once_with(table_name)
        self.assertDictEqual(self._dynamo_method.call_args.kwargs,
                             {'TransactItems': [expected_item]})

    def test_handles_transaction_failed(self):
        error_response = {'Error': {'Code': 'TransactionCanceledException'}}
        self._dynamo_method.side_effect = db.ClientError(error_response,
                                                         'TransactWriteItems')
        with self.assertRaises(db.TransactionError):
            self._call_test_fn()


class TestVerifyKey(DatabaseTestCase, QueryTestMixin):

    def _call_test_fn(self, index_name=None):
        database = Database('my-table')
        return database.verify_key(self._pk, self._sk, index_name=index_name)

    def test_handles_client_error(self):
        self._table.query.side_effect = ClientError({}, 'name')
        self.assertFalse(self._call_test_fn())
        self._mocks['logging'].error.assert_called_once()

    def test_correct_key(self):
        exp_cond = Key('PK').eq(str(self._pk)) & Key('SK').eq(str(self._sk))
        self._test_correct_key(exp_cond)

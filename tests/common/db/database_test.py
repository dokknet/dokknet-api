from abc import ABC, abstractmethod
from unittest.mock import MagicMock

from boto3.dynamodb.conditions import Key

from botocore.exceptions import ClientError

from app.common import db
from app.common.db.database import Database

from tests import TestBase


class User(db.EntityName):
    pass


class Subscription(db.EntityName):
    pass


class TestRemoveEntityPrefix(TestBase):
    def _test_val(self, prefix, val):
        res = Database._remove_entity_prefix(f'{prefix}{val}')
        self.assertEqual(val, res)

    def test_noop_on_no_match(self):
        val = 'foo'
        res = Database._remove_entity_prefix(val)
        self.assertEqual(val, res)

    def test_removes_class_uppercase(self):
        prefix = 'A1B2_CD3#'
        val = 'foo'
        self._test_val(prefix, val)

    def test_handles_multiple_hashes(self):
        prefix = 'PREFIX#'
        val = '#foo#bar#'
        self._test_val(prefix, val)

    def test_handles_pipe(self):
        prefix = 'PREFIX#'
        val = 'foo|bar'
        self._test_val(prefix, val)


class TestStripPrefixes(TestBase):
    def setUp(self):
        self._pk = db.PartitionKey(User, 'foo@example.com')
        self._sk = db.SortKey(Subscription, 'docs.example.com')

    def test_noop_on_no_prefix(self):
        item = {
            'foo': 'bar'
        }
        res = Database._strip_prefixes(item)
        self.assertDictEqual(item, res)

    def test_strips_prefixes(self):
        item = {
            'PK': str(self._pk),
            'SK': str(self._sk),
            'Foo': str(self._sk)
        }
        res = Database._strip_prefixes(item)
        self.assertEqual(res['PK'], self._pk.value)
        self.assertEqual(res['SK'], self._sk.value)
        self.assertEqual(res['Foo'], self._sk.value)

    def test_makes_copy(self):
        item = {
            'PK': str(self._pk),
            'SK': str(self._sk)
        }
        res = Database._strip_prefixes(item)
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


class DatabaseTestCaseMixin(ABC):
    _to_patch = [
        'app.common.db.database.boto3',
        'app.common.db.database.Database._table#PROPERTY',
        'app.common.db.database.Database._client#PROPERTY'
    ]

    @abstractmethod
    def _call_test_fn(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def _dynamo_method(self):
        raise NotImplementedError

    def setUp(self):
        super().setUp()

        self._client = MagicMock()
        self._mocks['_client'].return_value = self._client
        self._table = MagicMock()
        self._mocks['_table'].return_value = self._table
        self._pk = db.PartitionKey(User, 'foo@example.com')
        self._sk = db.SortKey(Subscription, 'docs.example.com')
        self._sk_prefix = db.PrefixSortKey(Subscription)

    def test_handlers_client_error(self):
        self._dynamo_method.side_effect = ClientError({}, 'OpName')
        with self.assertRaises(db.DatabaseError):
            self._call_test_fn()

    def test_handlers_throughput_error(self):
        error_response = {
            'Error': {
                'Code': 'ProvisionedThroughputExceededException',
            }
        }
        self._dynamo_method.side_effect = ClientError(error_response,
                                                      'OpName')
        with self.assertRaises(db.CapacityError):
            self._call_test_fn()


class TestDeleteItem(DatabaseTestCaseMixin, TestBase):
    def _call_test_fn(self, table_name='my-table'):
        database = Database(table_name)
        return database.delete_item(self._pk, self._sk)

    @property
    def _dynamo_method(self):
        return self._table.delete_item

    def test_key(self):
        self._call_test_fn()
        key_arg = self._dynamo_method.call_args.kwargs['Key']
        exp_key_arg = {
            'PK': str(self._pk),
            'SK': str(self._sk)
        }
        self.assertDictEqual(key_arg, exp_key_arg)


class QueryTestMixin(DatabaseTestCaseMixin):
    def _test_correct_key(self, exp_cond):
        self._call_test_fn()
        kc = self._dynamo_method.call_args.kwargs['KeyConditionExpression']
        self.assertEqual(kc, exp_cond)

    def test_handles_no_result(self):
        self._dynamo_method.return_value = {}
        self.assertFalse(self._call_test_fn())

    def test_handles_empty_result(self):
        self._dynamo_method.return_value = {'Items': []}
        self.assertFalse(self._call_test_fn())


class TestQuery(QueryTestMixin, TestBase):
    def _call_test_fn(self, table_name='my-table'):
        database = Database(table_name)
        key_cond = Key('PK').eq(str(self._pk))
        query_arg = db.QueryArg(key_cond)
        return database._query(query_arg)

    @property
    def _dynamo_method(self):
        return self._table.query

    def test_strips_prefixes(self):
        self._dynamo_method.return_value = {
            'Items': [{'PK': str(self._pk)}]
        }
        res = self._call_test_fn()
        self.assertEqual(res[0]['PK'], self._pk.value)


class TestGetItem(QueryTestMixin, TestBase):
    def _call_test_fn(self, attributes=None):
        database = Database('my-table')
        return database.get_item(self._pk, self._sk,
                                 attributes=attributes)

    @property
    def _dynamo_method(self):
        return self._table.query

    def test_correct_key(self):
        pk_cond = Key('PK').eq(str(self._pk))
        sk_cond = Key('SK').eq(str(self._sk))
        self._test_correct_key(pk_cond & sk_cond)

    def test_strips_prefixes(self):
        self._dynamo_method.return_value = {
            'Items': [{'PK': str(self._pk)}]
        }
        res = self._call_test_fn()
        self.assertEqual(res['PK'], self._pk.value)


class TestQueryPrefix(QueryTestMixin, TestBase):
    def _call_test_fn(self, attributes=None):
        database = Database('my-table')
        return database.query_prefix(self._pk, self._sk_prefix,
                                     attributes=attributes)

    @property
    def _dynamo_method(self):
        return self._table.query

    def test_correct_key(self):
        pk_cond = Key('PK').eq(str(self._pk))
        sk_cond = Key('SK').begins_with(str(self._sk_prefix))
        self._test_correct_key(pk_cond & sk_cond)


class PutItemTestMixin(DatabaseTestCaseMixin):
    def test_handles_conditional_check_failed(self):
        error_response = {'Error': {'Code': 'ConditionalCheckFailedException'}}
        self._dynamo_method.side_effect = ClientError(error_response,
                                                      'PutItem')
        with self.assertRaises(db.ConditionalCheckFailedError):
            self._call_test_fn()


class TestPutItem(PutItemTestMixin, TestBase):
    def _call_test_fn(self, table_name='my-table'):
        database = Database(table_name)
        put_arg = db.PutArg(self._pk, self._sk)
        return database.put_item(put_arg)

    @property
    def _dynamo_method(self):
        return self._client.put_item


class TestTransactWriteItems(PutItemTestMixin, TestBase):

    def _call_test_fn(self, items=None, table_name='my-table'):
        database = Database(table_name)
        if not items:
            items = []
        return database.transact_write_items(items)

    @property
    def _dynamo_method(self):
        return self._client.transact_write_items

    def _setup_error(self, message=''):
        error_response = {
            'Error': {
                'Code': 'TransactionCanceledException',
                'Message': message
            }
        }
        self._dynamo_method.side_effect = ClientError(error_response,
                                                      'TransactWriteItems')

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
        self._setup_error()
        with self.assertRaises(db.TransactionError):
            self._call_test_fn()

    def test_handles_conditional_check_failed(self):
        self._setup_error('ConditionalCheckFailed')
        with self.assertRaises(db.ConditionalCheckFailedError):
            self._call_test_fn()

    def test_handles_transaction_conflict(self):
        self._setup_error('TransactionConflict')
        with self.assertRaises(db.TransactionConflict):
            self._call_test_fn()


class TestUpdateItem(DatabaseTestCaseMixin, TestBase):
    def _call_test_fn(self, table_name='my-table'):
        database = Database(table_name)
        put_attributes = {
            'foo': 'bar'
        }
        update_arg = db.UpdateArg(self._pk, self._sk,
                                  put_attributes=put_attributes)
        return database.update_item(update_arg)

    @property
    def _dynamo_method(self):
        return self._client.update_item

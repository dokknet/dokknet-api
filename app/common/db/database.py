import copy
import re
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

import boto3
import boto3.dynamodb.conditions as cond

import botocore.client
from botocore.exceptions import ClientError

from app.common.db.keys import PartitionKey, PrefixSortKey, SortKey
from app.common.db.op_args import Attributes, InsertArg, OpArg, PutArg, \
    QueryArg, UpdateArg


ItemResult = Mapping[str, Any]


class DatabaseError(Exception):
    """Raised when a database error occurred without a more specific reason.

    All other database errors inherit from this.
    """


class CapacityError(DatabaseError):
    """Raised when a ProvisionedThroughputExceededException is raised."""


class ConditionalCheckFailedError(DatabaseError):
    """Raised when inserting an item failed because it already exists."""


class TransactionError(DatabaseError):
    """Raised when a transaction failed without a more specific reason."""


class TransactionConflict(TransactionError):
    """The transaction failed due to conflict from an other transaction."""


class Database:
    """DynamoDB single table pattern.

    Databases instances are not safe to share across threads.
    """

    @staticmethod
    @contextmanager
    def _dispatch_client_error() -> Iterator[None]:
        """Raise appropriate exception based on ClientError code."""
        try:
            yield None
        except ClientError as e:
            db_error = e.response.get('Error', {})
            code = db_error.get('Code')
            if code == 'ConditionalCheckFailedException':
                raise ConditionalCheckFailedError(e)
            if code == 'ProvisionedThroughputExceededException':
                raise CapacityError(e)
            elif code == 'TransactionCanceledException':
                message = db_error.get('Message', '')
                if 'ConditionalCheckFailed' in message:
                    raise ConditionalCheckFailedError(e)
                elif 'TransactionConflict' in message:
                    raise TransactionConflict(e)
                else:
                    raise TransactionError(e)
            else:
                raise DatabaseError(e)

    @staticmethod
    def _remove_entity_prefix(string: str) -> str:
        # Entity names are upper-cased Python class names.
        pattern = r'^[A-Z0-9_]+#(.+)$'
        match = re.match(pattern, string)
        if match:
            return match.group(1)
        else:
            return string

    @classmethod
    def _strip_prefixes(cls, item: Dict[str, Any]) -> ItemResult:
        """Strip entity prefixes from a DB item."""
        item_copy = copy.deepcopy(item)
        for k, v in item_copy.items():
            if isinstance(v, str):
                item_copy[k] = cls._remove_entity_prefix(v)
        return item_copy

    def __init__(self, table_name: str):
        """Initialize a Database instance.

        Args:
            table_name: The DynamoDB table name.

        """
        self._table_name = table_name
        # The boto objects are lazy-initialzied connections are created until
        # the first request.
        self._client_handle = boto3.client('dynamodb')
        # Not all operations are exposed on the table, but it's easier to work
        # with those from the table that it exposes.
        # Can't reuse client for table, as adding the client to a table puts
        # it into a mode where it converts {'PK': {'S': 'key-value'}} argument
        # to `{'PK': {'M': {'S': 'key-value'}}}` and this breaks
        # `transact_write_items`.
        resource = boto3.resource('dynamodb')
        self._table_handle = resource.Table(self._table_name)

    @property
    def _client(self) -> 'botocore.client.DynamoDB':
        # Helps mock the client at test time.
        return self._client_handle

    @property
    def _table(self) -> 'boto3.resources.factory.dynamodb.Table':
        # Helps mock the table at test time.
        return self._table_handle

    def _query(self, query_arg: QueryArg) -> List[ItemResult]:
        args = query_arg.get_kwargs(self._table_name)
        with self._dispatch_client_error():
            query_res = self._table.query(**args)
        items = query_res.get('Items', [])
        return [self._strip_prefixes(item) for item in items]

    def delete_item(self, pk: PartitionKey, sk: SortKey) -> None:
        """Delete an item from the database.

        The operation is idempotent.

        Args:
            pk: The primary key.
            sk: The sort key.

        """
        args = {
            'Key': {
                'PK': str(pk),
                'SK': str(sk)
            }
        }
        with self._dispatch_client_error():
            self._table.delete_item(**args)

    def get_item(self, pk: PartitionKey, sk: SortKey,
                 attributes: Optional[List[str]] = None,
                 consistent: bool = False) -> Optional[ItemResult]:
        """Fetch an item by its primary key from the database.

        Args:
            pk: The primary key.
            sk: The sort key.
            attributes: The attributes to get. Defaults to `['SK']`.
            consistent: Whether the read is strongly consistent or not.

        Returns:
            The item if it exists.

        """
        key_cond = cond.Key('PK').eq(str(pk)) & cond.Key('SK').eq(str(sk))
        query_arg = QueryArg(key_cond,
                             attributes=attributes,
                             consistent=consistent,
                             limit=1)
        # `Table.get_item` doesn't allow specifying index.
        res = self._query(query_arg)
        if res:
            return res[0]
        else:
            return None

    # Type checks are sufficient to test this function, so it's excluded from
    # unit test coverage.
    def insert(self, pk: PartitionKey, sk: SortKey,
               attributes: Optional[Attributes] = None) -> None:  # pragma: no cover  # noqa 501
        """Insert a new item into the database.

        The UpdateAt attribute of the item is automatically set.
        The insert fails if an item with the same composite key (PK, SK)
        exists.

        Args:
            pk: The partition key.
            sk: The sort key.
            attributes: Dictionary with additional attributes of the item.

        Raises:
            app.common.db.ItemExistsError if the item with the same composite
                key already exists.
            app.common.db.DatabaseError if there was a problem connecting to
                the database.

        """
        put_arg = InsertArg(pk, sk, attributes=attributes)
        self.put_item(put_arg)

    def put_item(self, put_arg: PutArg) -> None:
        """Insert a new item or replace an existing item.

        Args:
            put_arg: The put item op argument.

        Raises:
            app.common.db.DatabaseError if there was a problem connecting to
                the database.

        """
        kwargs = put_arg.get_kwargs(self._table_name)
        with self._dispatch_client_error():
            self._client.put_item(**kwargs)

    # Type checks are sufficient to test this function, so it's excluded from
    # unit test coverage.
    def query(self, key_condition: cond.Key,
              attributes: Optional[List[str]] = None,
              consistent: bool = False,
              limit: Optional[int] = None) -> List[ItemResult]:  # pragma: no cover  # noqa 501
        """Fetch items from the database based on a key condition.

        Doesn't support pagination.

        Args:
            key_condition: The key condition. Eg.:
                `Key('PK').eq(str(pk)) & Key('SK').begins_with(str(sk))`
            attributes: The attributes to get. Defaults to `SK`.
            consistent: Whether the read is strongly consistent or not.
            limit: The maximum number of items to fetch. Defaults to 1000.

        Returns:
            The requested items with the entity name prefixes stripped,
            eg. if the value of an attribute is 'USER#foo@example.com',
            only 'foo@example.com' is returned.

        Raises:
            app.common.db.DatabaseError if there was an error querying the
                database.

        """
        query_arg = QueryArg(key_condition,
                             attributes=attributes,
                             consistent=consistent,
                             limit=limit)
        return self._query(query_arg)

    def query_prefix(self, pk: PartitionKey, sk: PrefixSortKey,
                     attributes: Optional[List[str]] = None,
                     consistent: bool = False,
                     limit: Optional[int] = None) -> List[ItemResult]:
        """Fetch a items from the database based on a sort key prefix.

        Doesn't support pagination.

        Args:
            pk: The partition key.
            sk: The sort key prefix.
            attributes: The attributes to get. Defaults to `['SK']`.
            consistent: Whether the read is strongly consistent or not.
            limit: The maximum number of items to fetch. Defaults to 1000.

        Returns:
            The requested items with the `PK` and `SK` prefixes stripped.

        Raises:
            app.common.db.DatabaseError if there was an error querying the
                database.

        """
        key_condition = cond.Key('PK').eq(str(pk)) & \
            cond.Key('SK').begins_with(str(sk))
        query_arg = QueryArg(key_condition,
                             attributes=attributes,
                             consistent=consistent,
                             limit=limit)
        return self._query(query_arg)

    def transact_write_items(self, args: Iterable[OpArg]) -> None:
        """Write multiple items in a transaction.

        Note

        Args:
            args: Write OP args.

        Raises:
            app.common.db.TransactionError if the transaction fails.
            app.common.db.DatabaseError if there was a problem connecting to
                the database.

        """
        transact_items = []
        for a in args:
            kwargs = a.get_kwargs(self._table_name)
            transact_items.append({a.op_name: kwargs})
        with self._dispatch_client_error():
            self._client.transact_write_items(TransactItems=transact_items)

    def update_item(self, update_arg: UpdateArg) -> None:
        """Update an item or insert a new item if it doesn't exist.

        Args:
            update_arg: The update item op argument.

        Raises:
            app.common.db.DatabaseError if there was a problem connecting to
                the database.

        """
        kwargs = update_arg.get_kwargs(self._table_name)
        with self._dispatch_client_error():
            self._client.update_item(**kwargs)

    # Type checks are sufficient to test this function, so it's excluded from
    # unit test coverage.
    def put_attributes(self, pk: PartitionKey, sk: SortKey,
                       attributes: Attributes) -> None:  # pragma: no cover
        """Update an item or insert a new item if it doesn't exist.

        The `UpdatedAt` attribute of the item is automatically set.

        Args:
            pk: The partition key.
            sk: The sort key.
            attributes: Dictionary with attributes to put. These attributes
                will overwritten if they exist or created if they don't exist.

        Raises:
            app.common.db.DatabaseError if there was a problem connecting to
                the database.

        """
        update_arg = UpdateArg(pk, sk, put_attributes=attributes)
        self.update_item(update_arg)

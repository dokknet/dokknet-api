import copy
import hashlib
import logging
from contextlib import contextmanager
from typing import Iterable, Iterator, List, Optional, TypedDict

import boto3
from boto3.dynamodb.conditions import Key

import botocore.client
from botocore.exceptions import ClientError

from app.common.db.keys import AnySortKey, FullSortKey, PartitionKey
from app.common.db.op_args import Attributes, InsertArg, OpArg


class ItemResult(TypedDict, total=False):
    """An item from the database."""

    PK: str
    SK: str
    ExpiresAt: int
    UpdatedAt: str


class ItemExistsError(Exception):
    """Raised when inserting an item failed because it already exists."""


class TransactionError(Exception):
    """Raised when a transaction failed."""


class TooManyResultsError(Exception):
    """Raised when a a fetch query returns more than 1 result."""


class Database:
    """DynamoDB single table pattern."""

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
                raise ItemExistsError(e)
            elif code == 'TransactionCanceledException':
                raise TransactionError(e)
            else:
                raise e

    @staticmethod
    def _remove_prefix(prefix: str, string: str) -> str:
        if string.startswith(prefix):
            return string[len(prefix):]
        else:
            raise ValueError(
                f'String {string} doesn\'t start with prefix {prefix}')

    @staticmethod
    def hex_hash(value: bytes) -> str:
        """Get the SHA3-256 hex hash of the value.

        Args:
            value: The value to hash.

        Returns:
            The hash as a hex digest.

        """
        m = hashlib.sha3_256()
        m.update(value)
        return m.hexdigest()

    @classmethod
    def _strip_prefixes(cls, pk: PartitionKey, sk: AnySortKey,
                        item: ItemResult) -> ItemResult:
        """Strip prefixes of PK and SK values from a DB item."""
        item_copy = copy.deepcopy(item)
        if 'PK' in item:
            item_copy['PK'] = cls._remove_prefix(pk.prefix, item['PK'])
        if 'SK' in item:
            # If SK is a `SingleSortKey` this results in the empty string.
            item_copy['SK'] = cls._remove_prefix(sk.prefix, item['SK'])
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

    def fetch(self, pk: PartitionKey, sk: AnySortKey,
              index_name: Optional[str] = None,
              attributes: Optional[List[str]] = None) -> Optional[ItemResult]:
        """Fetch a single item from the database.

        Args:
            pk: The partition key.
            sk: The sort key.
            index_name: Optional global secondary index name.
            attributes: The attributes to get. Defaults to ['PK', 'SK'].

        Returns:
            Whether the key exists in the database.

        Raises:
            app.common.db.ClientError if there was an error querying the
                database.
            app.common.db.TooManyResultsError if more than one items were
                returned for the query.

        """
        key_cond = Key('PK').eq(str(pk)) & Key('SK').begins_with(str(sk))
        args = {
            'Select': 'SPECIFIC_ATTRIBUTES',
            'KeyConditionExpression': key_cond
        }

        if index_name:
            args['IndexName'] = index_name

        if attributes:
            args['AttributesToGet'] = attributes
        else:
            args['AttributesToGet'] = ['PK', 'SK']

        res = self._table.query(**args)
        items = res.get('Items', [])
        if len(items) == 0:
            return None
        elif len(items) == 1:
            return self._strip_prefixes(pk, sk, items[0])
        else:
            raise TooManyResultsError(
                f'Multiple items returned when fetching ({pk}, {sk})')

    def insert(self, pk: PartitionKey, sk: FullSortKey,
               attributes: Optional[Attributes] = None) -> None:
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
            app.common.db.ClientError if there was a problem connecting to the
                database.

        """
        put_arg = InsertArg(pk, sk, attributes=attributes)
        kwargs = put_arg.get_kwargs(self._table_name)
        with self._dispatch_client_error():
            self._client.put_item(**kwargs)

    def transact_write_items(self, args: Iterable[OpArg]) -> None:
        """Write multiple items in a transaction.

        Args:
            args: Write OP args.

        Raises:
            app.common.db.TransactionError if the transaction fails.
            app.common.db.ClientError if there was a problem connecting to the
                database.

        """
        transact_items = []
        for a in args:
            kwargs = a.get_kwargs(self._table_name)
            transact_items.append({a.op_name: kwargs})
        with self._dispatch_client_error():
            self._client.transact_write_items(TransactItems=transact_items)

    def verify_key(self, pk: PartitionKey, sk: FullSortKey,
                   index_name: Optional[str] = None) -> bool:
        """Check whether a key exists in the database.

        Args:
            pk: The primary key.
            sk: The secondary key.
            index_name: Optional global secondary index name.

        Returns:
            Whether the key exists in the database.

        """
        key_cond = Key('PK').eq(str(pk)) & Key('SK').eq(str(sk))
        args = {
            'Select': 'SPECIFIC_ATTRIBUTES',
            'AttributesToGet': ['PK'],
            'KeyConditionExpression': key_cond,
            'Limit': 1
        }
        if index_name:
            args['IndexName'] = index_name
        try:
            res = self._table.query(**args)
        except ClientError as e:
            logging.error(f'Failed to verify key due to client error:\n{e}')
            return False

        items = res.get('Items', [])
        return len(items) > 0

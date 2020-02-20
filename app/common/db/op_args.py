"""DynamoDB operation arguments."""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, List, Mapping, Optional, Union, cast

import boto3.dynamodb.conditions as cond
from boto3.dynamodb.types import TypeSerializer

from app.common.db.keys import PartitionKey, SortKey

_DynamoValue = Union[str, bool]

# Can't narrow value types down, because of TypedDict-Mapping
# incompatibiltiy. See https://stackoverflow.com/q/60304154
Attributes = Mapping[str, Any]
Kwargs = Mapping[str, Any]


class OpArg(ABC):
    """DynamoDB operation argument base class."""

    @staticmethod
    def _iso_now() -> str:
        now = datetime.utcnow()
        return now.replace(microsecond=0).isoformat()

    def __init__(self) -> None:
        """Initialize an OpArg instance."""
        self._serializer = TypeSerializer()

    @property
    @abstractmethod
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument.

        Must correspond to TransactWriteItem argument.
        """
        raise NotImplementedError

    @abstractmethod
    def get_kwargs(self, table_name: str) -> Kwargs:
        """Get key-word arguments that can be passed to the DynamoDB operation.

        Args:
            table_name: The DynamoDB table name for the operation.

        Returns:
            The key-word arguments.

        """
        raise NotImplementedError

    def _serialize_val(self, val: Any) -> Kwargs:
        """Serialize a value to a DynamoDB value."""
        return cast(Kwargs, self._serializer.serialize(val))

    def _serialize_dict(self, item: Attributes) -> Kwargs:
        """Serialize a dictionary while preserving its top level keys."""
        return {k: self._serialize_val(v) for k, v in item.items()}

    def _serialize_keys(self, pk: PartitionKey, sk: SortKey) \
            -> Mapping[str, Mapping[str, _DynamoValue]]:
        """Serialize composite key."""
        item: Attributes = {
            'PK': str(pk),
            'SK': str(sk),
        }
        return self._serialize_dict(item)


class DeleteArg(OpArg):
    """Argument to a DynamoDB DeleteItem operation."""

    def __init__(self, pk: PartitionKey, sk: SortKey,
                 idempotent: bool = True):
        """Initialize a DeleteArg instance.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            idempotent: If false, the op raises an error if the item to
                delete doesn't exist. Defaults to to true.

        """
        super().__init__()
        self._pk = pk
        self._sk = sk
        self._idempotent = idempotent

    @property
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument."""
        return 'Delete'

    def get_kwargs(self, table_name: str) -> Kwargs:
        """Get key-word arguments that can be passed to a DeleteItem operation.

        Args:
            table_name: The DynamoDB table name for the DeleteItem operation.

        Returns:
            The key-word arguments.

        """
        kwargs = {
            'TableName': table_name,
            'Key': self._serialize_keys(self._pk, self._sk)
        }
        if not self._idempotent:
            # This check is performed after the item is retrieved by the
            # composite key, so no need to specify SK.
            kwargs['ConditionExpression'] = 'attribute_exists(PK)'

        return kwargs


class PutArg(OpArg):
    """Argument to a DynamoDB PutItem operation.

    This op will replace the entire item. User `UpdateArg` if you just want to
    update a specific attribute.

    The `CreatedAt` attribute of the item is automatically set to the current
    ISO timestamp without microseconds (eg. '2020-02-15T19:09:38').

    """

    def __init__(self, pk: PartitionKey, sk: SortKey,
                 attributes: Optional[Attributes] = None,
                 allow_overwrite: bool = True):
        """Initialize a PutArg instance.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            attributes: Optional additional attributes of the item.
            allow_overwrite: Whether to allow overwriting an existing item.

        """
        super().__init__()
        self._pk = pk
        self._sk = sk
        self._attributes = attributes
        self._allow_overwrite = allow_overwrite

    @property
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument."""
        return 'Put'

    def _get_dynamo_item(self) -> Mapping[str, Mapping[str, _DynamoValue]]:
        keys_item = self._serialize_keys(self._pk, self._sk)

        item: Attributes = {
            'CreatedAt': self._iso_now()
        }
        if self._attributes:
            # `item` keys overwrite `_attributes` keys
            item = {**self._attributes, **item}

        dynamo_item = self._serialize_dict(item)
        return {**dynamo_item, **keys_item}

    def get_kwargs(self, table_name: str) -> Kwargs:
        """Get key-word arguments that can be passed to a PutItem operation.

        Args:
            table_name: The DynamoDB table name for the PutItem operation.

        Returns:
            The key-word arguments.

        """
        kwargs = {
            'TableName': table_name,
            'Item': self._get_dynamo_item()
        }
        if not self._allow_overwrite:
            # The condition only checks if the item with the same composite key
            # exists. Ie. if there is an item (PK=foo, SK=0) in the database,
            # and we insert a new item (PK=foo, SK=1), the insert will succeed.
            kwargs['ConditionExpression'] = 'attribute_not_exists(PK)'

        return kwargs


class InsertArg(PutArg):
    """DynamoDB PutItem argument that prevents overwriting existing items."""

    def __init__(self, pk: PartitionKey, sk: SortKey,
                 attributes: Optional[Attributes] = None):
        """Initialize an InsertArg instance.

        The `UpdateAt` attribute of the item is automatically set.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            attributes: Optional additional attributes of the item.

        """
        super().__init__(pk, sk,
                         attributes=attributes,
                         allow_overwrite=False)


class QueryArg(OpArg):
    """DynamoDB query operation argument.

    Note that query can not be used in a transaction, the purpose of this class
    is to provide a simplified interface to the boto3 DynamoDB table class.

    """

    _max_limit = 1000

    def __init__(self, key_condition: cond.Key,
                 attributes: Optional[List[str]] = None,
                 consistent: bool = False,
                 limit: Optional[int] = None):
        """Initialize a QueryArg instance.

        Args:
            key_condition: The key condition. Eg.:
                `Key('PK').eq(str(pk)) & Key('SK').begins_with(str(sk))`
            attributes: The attributes to get. Defaults to `SK`.
            consistent: Whether the read is strongly consistent or not.
            limit: The maximum number of items to fetch. Defaults to 1000 which
                is also the maximum allowed value.

        """
        self._key_cond = key_condition
        self._attributes = attributes
        self._consistent = consistent
        if limit is not None:
            if limit > self._max_limit:
                raise ValueError(f'Limit {limit} is greater than max '
                                 f'{self._max_limit}')
            self._limit = limit
        else:
            self._limit = self._max_limit

    @property
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument.

        Note that query can not be used in a transaction.

        """
        return 'Query'

    def get_kwargs(self, table_name: str) -> Kwargs:
        """Get key-word arguments that can be passed to a boto3 DynamoDB table.

        Args:
            table_name: The DynamoDB table name for the operation.

        Returns:
            The key-word arguments.

        """
        args = {
            'Select': 'SPECIFIC_ATTRIBUTES',
            'KeyConditionExpression': self._key_cond,
            'ConsistentRead': self._consistent,
            'Limit': self._limit
        }
        if self._attributes:
            args['ProjectionExpression'] = ','.join(self._attributes)
        else:
            args['ProjectionExpression'] = 'SK'
        return args


class UpdateArg(OpArg):
    """Argument to a DynamoDB UpdateItem operation.

    This op updates the specified attributes or creates a new item if it
    doesn't exist yet.

    The `UpdatedAt` attribute of the item is automatically set to the current
    ISO timestamp without microseconds (eg. '2020-02-15T19:09:38').

    """

    def __init__(self, pk: PartitionKey, sk: SortKey,
                 put_attributes: Optional[Attributes] = None):
        """Initialize an UpdateArg instance.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            put_attributes: Optional attributes to put for the item. These
                attributes will be overwritten if they exist, or created if
                they don't exist.

        """
        super().__init__()
        self._pk = pk
        self._sk = sk
        self._put_attributes = put_attributes

    @property
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument."""
        return 'Update'

    def _get_put_updates(self) -> Mapping[str, Mapping[str, Any]]:
        item = {
            'UpdatedAt': self._iso_now()
        }
        if self._put_attributes:
            # `item` keys overwrite `_attributes` keys
            item = {**self._put_attributes, **item}
        res = {}
        for k, v in item.items():
            res[k] = {
                'Action': 'PUT',
                'Value': self._serialize_val(v)
            }
        return res

    def _get_attr_updates(self) -> Mapping[str, Mapping[str, _DynamoValue]]:
        # TODO (abiro) add DELETE
        return self._get_put_updates()

    def get_kwargs(self, table_name: str) -> Kwargs:
        """Get key-word arguments that can be passed to a PutItem operation.

        Args:
            table_name: The DynamoDB table name for the PutItem operation.

        Returns:
            The key-word arguments.

        """
        keys = self._serialize_keys(self._pk, self._sk)
        attr_updates = self._get_attr_updates()
        kwargs = {
            'TableName': table_name,
            'Key': keys,
            'AttributeUpdates': attr_updates
        }
        return kwargs

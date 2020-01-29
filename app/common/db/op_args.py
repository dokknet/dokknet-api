"""DynamoDB operation arguments."""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, Union

from app.common.db.keys import FullSortKey, PartitionKey

_DynamoValue = Union[str, bool]

AttributeValues = Union[str, int, float, bool]
Attributes = Dict[str, AttributeValues]
Kwargs = Dict[str, Any]


class OpArg(ABC):
    """DynamoDB operation argument base class."""

    @staticmethod
    def _get_dynamo_val(value: AttributeValues) -> Dict[str, _DynamoValue]:
        dynamo_type: str
        dynamo_value: _DynamoValue
        if isinstance(value, bool):
            dynamo_type = 'BOOL'
            dynamo_value = value
        elif isinstance(value, (int, float)):
            dynamo_type = 'N'
            dynamo_value = str(value)
        else:
            dynamo_type = 'S'
            dynamo_value = str(value)

        return {dynamo_type: dynamo_value}

    @classmethod
    def _dict_to_dynamo_vals(cls, item: Attributes) -> Kwargs:
        return {k: cls._get_dynamo_val(v) for k, v in item.items()}

    @classmethod
    def _get_dynamo_keys(cls, pk: PartitionKey, sk: FullSortKey) \
            -> Dict[str, Dict[str, _DynamoValue]]:
        item: Attributes = {
            'PK': str(pk),
            'SK': str(sk),
        }
        return cls._dict_to_dynamo_vals(item)

    @abstractmethod
    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize an OpArg instance."""
        raise NotImplementedError

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


class PutArg(OpArg):
    """Argument to a DynamoDB PutItem operation."""

    @staticmethod
    def _get_updated_at() -> str:
        return str(datetime.utcnow())

    def __init__(self, pk: PartitionKey, sk: FullSortKey,
                 attributes: Optional[Attributes] = None,
                 allow_overwrite: bool = True):
        """Initialize a PutArg instance.

        The `UpdateAt` attribute of the item is automatically set.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            attributes: Optional additional attributes of the item.
            allow_overwrite: Whether to allow overwriting an existing item.

        """
        self._pk = pk
        self._sk = sk
        self._attributes = attributes
        self._allow_overwrite = allow_overwrite

    @property
    def op_name(self) -> str:
        """Get the operation name for which this object is an argument."""
        return 'Put'

    def _get_dynamo_item(self) -> Dict[str, Dict[str, _DynamoValue]]:
        keys_item = self._get_dynamo_keys(self._pk, self._sk)

        item: Attributes = {
            'UpdatedAt': self._get_updated_at()
        }
        if self._attributes:
            # `item` keys overwrite `_attributes` keys
            item = {**self._attributes, **item}

        dynamo_item = self._dict_to_dynamo_vals(item)
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

    def __init__(self, pk: PartitionKey, sk: FullSortKey,
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


class DeleteArg(OpArg):
    """Argument to a DynamoDB DeleteItem operation."""

    def __init__(self, pk: PartitionKey, sk: FullSortKey,
                 idempotent: bool = False):
        """Initialize a DeleteArg instance.

        Args:
            pk: The partition key of the item.
            sk: The sort key of the item.
            idempotent: If true, the op doesn't raise an error if the item to
            delete doesn't exist.

        """
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
            'Key': self._get_dynamo_keys(self._pk, self._sk)
        }
        if not self._idempotent:
            # This check is performed after the item is retrieved by the
            # composite key, so no need to specify SK.
            kwargs['ConditionExpression'] = 'attribute_exists(PK)'

        return kwargs

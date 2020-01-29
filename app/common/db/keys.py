"""This module contains the keys of entities and relations in the database.

Each item in the database is uniquely identified by its primary key.
The primary key is a composite of the partition key and the sort key.
The partition key for an item is the concatenation of its entity type and the
key value: `ENTITY#key`.
The sort key is `#ENTITY#` if the item does not model a relation and
`OTHER_ENTITY#other_key` if the item models a relation.
Sort keys without values may be used to query relations with a certain
entity type. For example, to query all the subscriptions of a user, one
would use the `USER#foo@example.com` partition key and the `SUBSCRIPTION#`
sort key.

The following entities are supported in the database (this is enforced by
`EntityType` literal type):

1. Domain
- type: `DOMAIN`
- key value: domain name
- example: `DOMAIN#docs.example.com`
2. Session
- type: `SESSION`
- key value: session id hex hash
- example: `SESSION#5302f768ab8a0ce4f5a616ecdff45f3b728c9c8f10ec1da68253cb8c6`
3. Subscription
- type: `SUBSCRIPTION`
- key value: domain name
- example: `SUBSCRIPTION#docs.example.com`
4. User
- type: `USER`
- key value: user email
- example: `USER#foo@example.com`

"""
from abc import ABC
from typing import Any, Literal, Optional, Union


EntityType = Literal[
    'ApiKey',
    'Domain',
    'Session',
    'Subscription',
    'User'
]
FullSortKey = Union['SortKey', 'SingleSortKey']
AnySortKey = Union['SortKey', 'PrefixSortKey', 'SingleSortKey']


class EntityKey(ABC):
    """Abstract base class of database keys."""

    @staticmethod
    def _get_prefix(entity_type: EntityType) -> str:
        prefix = entity_type.upper() + '#'
        return prefix

    def __init__(self, entity_type: EntityType, value: str):
        """Initialize an EntityKey instance.

        Args:
            entity_type: The entity type name.
            value: The key value.

        """
        self._prefix = self._get_prefix(entity_type)
        self._value = value

    def __str__(self) -> str:
        """Get the string representation."""
        # Eg. ENTITY#value
        return f'{self._prefix}{self._value}'

    def __eq__(self, other: Any) -> bool:
        """Compare semantic equality."""
        return str(self) == str(other)

    @property
    def prefix(self) -> str:
        """Get the entity prefix of the key."""
        return self._prefix

    @property
    def value(self) -> Optional[str]:
        """Get the value of the key."""
        return self._value


class PartitionKey(EntityKey):
    """Partition key."""


class SortKey(EntityKey):
    """Sort key with a value."""


class PrefixSortKey(EntityKey):
    """Prefix only sort key to query relations."""

    def __init__(self, entity_type: EntityType):
        """Initialize a PrefixSortKey instance.

        Args:
            entity_type: The entity type name.

        """
        super().__init__(entity_type, '')

    def __str__(self) -> str:
        """Get the string representation."""
        # Eg. ENTITY#
        return self._prefix


class SingleSortKey(EntityKey):
    """Sort key of an item that doesn't model a relation."""

    def __init__(self, entity_type: EntityType):
        """Initialize a SingleSortKey instance.

        Args:
            entity_type: The entity type name.

        """
        super().__init__(entity_type, '')
        # Eg. #ENTITY#
        self._prefix = f'#{self._prefix}'

    def __str__(self) -> str:
        """Get the string representation."""
        return self._prefix

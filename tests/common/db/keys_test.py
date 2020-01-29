import app.common.db.keys as m

from tests import TestBase


class TestGetPrefix(TestBase):
    def test_correct_prefix(self):
        self.assertEqual(m.EntityKey._get_prefix('User'), 'USER#')


class TestEq(TestBase):
    def test_self(self):
        pk = m.PartitionKey('User', 'value')
        self.assertEqual(pk, pk)

    def test_neq(self):
        pk_1 = m.PartitionKey('User', 'value')
        pk_2 = m.PartitionKey('User', 'value')
        self.assertEqual(pk_1, pk_2)

    def test_pk_eq_sq(self):
        pk = m.PartitionKey('User', 'value')
        sk = m.SortKey('User', 'value')
        self.assertEqual(pk, sk)


class TestPartitionKeyInit(TestBase):
    def test_value_not_optional(self):
        # This is type checked, but we want to make sure the implementation
        # doesn't change in this regard as that would violate the DynamoDB
        # single table pattern.
        with self.assertRaises(TypeError):
            m.PartitionKey('Domain')


class TestStrValueMixin:
    _constructor = None

    def test_value(self):
        value = 'value'
        pk_domain = self._constructor('Domain', value)
        self.assertEqual(pk_domain, f'DOMAIN#{value}')

    def test_different_types(self):
        value = 'value'
        pk_domain = self._constructor('Domain', value)
        pk_user = self._constructor('User', value)
        self.assertNotEqual(pk_domain, pk_user)


class TestPartitionKeyStr(TestBase, TestStrValueMixin):
    _constructor = m.PartitionKey


class TestSortKeyStr(TestBase, TestStrValueMixin):
    _constructor = m.SortKey


class TestPrefixSortKeyStr(TestBase):
    def test_no_value(self):
        sk_domain = m.PrefixSortKey('Subscription')
        self.assertEqual(sk_domain, 'SUBSCRIPTION#')


class TestSingleSortKeyStr(TestBase):
    def test_single_entity(self):
        sk_domain = m.SingleSortKey('Domain')
        self.assertEqual(sk_domain, '#DOMAIN#')


class TestSingleSortKeyPrefix(TestBase):
    def test_single_entity(self):
        sk_domain = m.SingleSortKey('Domain')
        self.assertEqual(sk_domain.prefix, '#DOMAIN#')


class TestRepr(TestBase):
    def test_pk_repr_no_leak(self):
        """Representation of PK shouldn't leak DB data."""
        value = 'pk-value-1234'
        pk = m.PartitionKey('Session', value)
        self.assertNotIn(value, repr(pk))

    def test_sk_repr_no_leak(self):
        """Representation of SK shouldn't leak DB data."""
        value = 'sk-value-5678'
        sk = m.SortKey('Session', value)
        self.assertNotIn(value, repr(sk))

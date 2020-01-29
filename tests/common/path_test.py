import app.common.path as m

from tests import TestBase


class TestParsePath(TestBase):
    def test_empty(self):
        p = m.parse_path('')
        self.assertEqual(p.name, '')
        self.assertEqual(len(p.parts), 0)

    def test_dots_in_path(self):
        domain = 'docs.example.com'
        p = m.parse_path(f'/foo/bar/{domain}')
        self.assertEqual(p.name, domain)

    def test_trailing_slash(self):
        p = m.parse_path('/foo/bar/')
        self.assertEqual(p.name, 'bar')
        # Root is separate part
        self.assertEqual(len(p.parts), 3)

    def test_decodes_unicode(self):
        p = m.parse_path('/El%20Ni%C3%B1o/')
        self.assertEqual(p.name, 'El Niño')

    def test_decodes_plus(self):
        p = m.parse_path('/fubar/foo+bar')
        self.assertEqual(p.name, 'foo bar')

    def test_relative_to(self):
        p = m.parse_path('/base/foo/bar', relative_to='/base')
        self.assertEqual(str(p), 'foo/bar')

    def test_relative_to_self(self):
        p = m.parse_path('/foo/bar', relative_to='/foo/bar')
        self.assertEqual(p.name, '')
        self.assertEqual(len(p.parts), 0)

    def test_expected_parts(self):
        # Shouldn't raise
        m.parse_path('/foo/bar', expected_parts=3)
        m.parse_path('foo/bar', expected_parts=2)

    def test_expected_parts_relative_to(self):
        # Shouldn't raise
        m.parse_path('/foo/bar', relative_to='/foo', expected_parts=1)

    def test_missing_part(self):
        with self.assertRaises(ValueError):
            m.parse_path('/foo/bar/', relative_to='/foo/bar/',
                         expected_parts=1)


class TestGetName(TestBase):
    def test_missing_name(self):
        with self.assertRaises(ValueError):
            m.get_name('/foo/bar/', '/foo/bar')

    def test_correct_name(self):
        name = m.get_name('/foo/bar/baz/', '/foo/bar')
        self.assertEqual(name, 'baz')

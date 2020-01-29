from pathlib import PurePosixPath
from typing import Optional
from urllib.parse import unquote_plus


def parse_path(path: str,
               relative_to: Optional[str] = None,
               expected_parts: Optional[int] = None) -> PurePosixPath:
    """Convert URL path string to Path object.

    Args:
        path: The path to parse.
        relative_to: Optional base to parse path relative to. Eg. if `path` is
            "/base/foo/bar" and `relative_to` is "/base/" the returned path
            will be "foo/bar".
        expected_parts: Expected number path parts (after `relative_to` is
            applied). Eg. "/foo/bar" has two parts.

    Returns:
        The url-decoded path as a Path object.

    Raises:
        ValueError if `relative_to` is not a prefix of `path` or the path
            doesn't have `expected_parts` number of parts.

    """
    p = PurePosixPath(unquote_plus(path))
    if relative_to:
        p = p.relative_to(relative_to)
    if expected_parts is not None and len(p.parts) != expected_parts:
        raise ValueError(f'Expected {path} to have {expected_parts} part(s) '
                         f'relative to {relative_to}.')

    return p


def get_name(path: str, base: str) -> str:
    """Get the name part of a path.

    Args:
        path: The path, eg. "/foo/bar/baz/".
        base: The expected base of the path, eg. "/foo/bar/".

    Returns:
        The part of the path after base, eg. "baz".

    Raises:
        ValueError if base is not a prefix of path or if the last part is
            missing relative to base.

    """
    p = parse_path(path, relative_to=base, expected_parts=1)
    return p.name

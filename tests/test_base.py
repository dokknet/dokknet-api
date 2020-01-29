import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Literal
from unittest import TestCase
from unittest.mock import MagicMock, PropertyMock, patch

_DeploymentTargets = Literal[
    'dev',
    'staging',
    'production'
]


class TestBase(TestCase):
    """Base class for unit tests."""

    _repo_root = Path(__file__).parents[1]

    # Paths in this list will be automatically patched for all test cases.
    # Overwrite in subclasses to populate the list.
    _to_patch: List[str] = []

    @staticmethod
    def _load_n_cache(base: Path, key: str, dictt: Dict[str, Any]) \
            -> Dict[str, Any]:
        if key not in dictt:
            fn = '{}.json'.format(key)
            with open(base / fn) as f:
                e = json.load(f)
                dictt[key] = e

        # Make deep copy as the result may be mutated.
        return deepcopy(dictt[key])

    def __init__(self, *args: str, **kwargs: str):
        """Initialize a TestBase instance.

        Args
            args: positional arguments for unittest.TestCase
            kwargs: keyword arguments for unittest.TestCase

        """
        super().__init__(*args, **kwargs)

        self._mocks: Dict[str, MagicMock]

        self._events: Dict[str, Any] = {}
        self._events_dir = self._repo_root / 'tests/handlers/events'

        self._configs: Dict[str, Any] = {}
        self._configs_dir = self._repo_root / 'app/common/configs'

    def get_event(self, event_name: str) -> Any:
        """Get a Lambda event by name.

        Args:
            event_name: The name of the event.

        Returns:
            The event as a dict.

        Raises:
            OSError if file is not found.

        """
        return self._load_n_cache(self._events_dir, event_name, self._events)

    def get_configs(self, deployment_target: _DeploymentTargets) -> Any:
        """Get Cloudformation template configs.

        Args:
            deployment_target: The deployment target to get configs for.

        Returns:
            The configs as a dict.

        Raises:
            OSError if file is not found.

        """
        return self._load_n_cache(self._configs_dir, deployment_target,
                                  self._configs)

    def setUp(self):
        self._mocks = {}
        for path in self._to_patch:
            if path.endswith('#PROPERTY'):
                path, _ = path.split('#PROPERTY')
                name = path.split('.')[-1]
                patcher = patch(path, new_callable=PropertyMock)
                prop_mock = patcher.start()
                self._mocks[name] = prop_mock
            else:
                patcher = patch(path)
                name = path.split('.')[-1]
                self._mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

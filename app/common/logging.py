import logging

from app.common.config import config

# Can't put into `app.__init__`, because that would cause circular dependency
# with `app.config`.
_logger = logging.getLogger('app')
_logger.setLevel(config.log_level)
_ch = logging.StreamHandler()
_fmt = logging.Formatter('%(asctime)s|%(name)s.%(funcName)s|%(levelname)s: %(message)s')  # noqa 501
_ch.setFormatter(_fmt)
_logger.addHandler(_ch)


def get_logger(name: str) -> logging.Logger:
    """Get logger for module name.

    The purpose of this function is to make sure that the hierarchical
    configuration is applied.

    Args:
        name: The module name (eg. __name__ for current module.)

    Returns:
        The logger.

    """
    return logging.getLogger(name)

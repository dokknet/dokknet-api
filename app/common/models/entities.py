"""Entities in the database.

The key for an item is composed of the entity name and the key value, eg. for
users: `USER#alice@example.com`.

"""
import app.common.db as db


class Group(db.EntityName):
    """A group of users.

    Value: uuid.

    """


class GroupTrialEnd(db.EntityName):
    """Group subscription trials ending on the same day.

    Value: date in ISO format as a string, eg. '2020-02-19'.

    """


class GroupSub(db.EntityName):
    """Group subscription to a project.

    Value: project domain name, eg. 'docs.example.com'.

    """


class Project(db.EntityName):
    """Documentation project.

    Value: project domain name, eg. 'docs.example.com'.

    """


class Session(db.EntityName):
    """User session for authorization on partner sites.

    Value: session id hex hash as string, eg. '5302f768ab8...'.

    """


class Sub(db.EntityName):
    """User subscription to a project.

    Value: project domain name, eg. 'docs.example.com'.

    """


class TrialEnd(db.EntityName):
    """User subscription trials ending on the same day.

    Value: date in ISO format as a string, eg. '2020-02-19'.

    """


class User(db.EntityName):
    """User info.

    Value: user's email address.

    """

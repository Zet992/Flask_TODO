import datetime

import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Project(SqlalchemyBase):
    __tablename__ = 'project'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
                           autoincrement=True)
    title = sqlalchemy.Column(sqlalchemy.String)
    messages = orm.relationship('Message')
    leader_id = sqlalchemy.Column(sqlalchemy.Integer,
                                 sqlalchemy.ForeignKey('user.id'))
    leader = orm.relationship('User', back_populates='projects')
    tasks = orm.relationship('Task')
    created = sqlalchemy.Column(sqlalchemy.DateTime,
                                default=datetime.datetime.now())
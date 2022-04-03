import datetime

import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Message(SqlalchemyBase):
    __tablename__ = 'message'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
                           autoincrement=True)
    body = sqlalchemy.Column(sqlalchemy.String)
    author_id = sqlalchemy.Column(sqlalchemy.Integer,
                                  sqlalchemy.ForeignKey('user.id'))
    author = orm.relationship('User', back_populates='messages')
    project_id = sqlalchemy.Column(sqlalchemy.Integer,
                                   sqlalchemy.ForeignKey('project.id'))
    created = sqlalchemy.Column(sqlalchemy.DateTime,
                                default=datetime.datetime.now())
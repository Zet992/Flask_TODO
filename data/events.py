import datetime

import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


class Event(SqlAlchemyBase):
    __tablename__ = 'event'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
                           autoincrement=True)
    title = sqlalchemy.Column(sqlalchemy.String)
    description = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    date = sqlalchemy.Column(sqlalchemy.Datetime,
                             default=datetime.datetime.now())
    author_id = sqlalchemy.Column(sqlalchemy.Integer,
                                  sqlalchemy.ForeignKey('user.id'))
    author = orm.relationship('User', back_populates='events')

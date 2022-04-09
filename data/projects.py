import datetime

import sqlalchemy
from sqlalchemy import orm

from .db_session import SqlAlchemyBase


project_to_user = sqlalchemy.Table(
    'project_to_user',
    SqlAlchemyBase.metadata,
    sqlalchemy.Column('project', sqlalchemy.Integer,
                      sqlalchemy.ForeignKey('project.id'),
                      primary_key=True),
    sqlalchemy.Column('user', sqlalchemy.Integer,
                      sqlalchemy.ForeignKey('user.id'),
                      primary_key=True)
)


class Project(SqlAlchemyBase):
    __tablename__ = 'project'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
                           autoincrement=True)
    title = sqlalchemy.Column(sqlalchemy.String)
    description = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    slug = sqlalchemy.Column(sqlalchemy.String)
    messages = orm.relationship('Message')
    leader_id = sqlalchemy.Column(sqlalchemy.Integer,
                                 sqlalchemy.ForeignKey('user.id'))
    leader = orm.relationship('User', back_populates='own_projects')
    members = orm.relationship('User', secondary=project_to_user,
                               back_populates='projects')
    tasks = orm.relationship('Task')
    created = sqlalchemy.Column(sqlalchemy.DateTime,
                                default=datetime.datetime.now())
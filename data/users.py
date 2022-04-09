import datetime

import sqlalchemy
from sqlalchemy import orm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from .db_session import SqlAlchemyBase
from .projects import project_to_user


class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'user'

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True,
                           autoincrement=True)
    name = sqlalchemy.Column(sqlalchemy.String, unique=True)
    age = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)
    birth_date = sqlalchemy.Column(sqlalchemy.Date, nullable=True)
    speciality = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String, unique=True,
                              index=True)
    hashed_password = sqlalchemy.Column(sqlalchemy.String)
    slug = sqlalchemy.Column(sqlalchemy.String, unique=True)
    created = sqlalchemy.Column(sqlalchemy.DateTime,
                                default=datetime.datetime.now())
    own_projects = orm.relationship('Project', back_populates='leader')
    projects = orm.relationship('Project', secondary=project_to_user,
                                back_populates='members')
    events = orm.relationship('Event', back_populates='author')
    messages = orm.relationship('Message', back_populates='author')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

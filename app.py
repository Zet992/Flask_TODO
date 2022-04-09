import re

from flask import Flask, render_template, url_for, request, redirect
from flask import abort, make_response, jsonify

from flask_login import LoginManager, login_required, login_user
from flask_login import logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, EmailField
from wtforms import BooleanField, DateTimeField
from wtforms.validators import DataRequired

from data import db_session
from data.users import User
from data.events import Event
from data.messages import Message
from data.projects import Project
from data.tasks import Task


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'special_secret_key'


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Repeat password',
                                   validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Submit')


class ProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])


def slugify(title):
    if not title:
        return None
    return re.sub(pattern, "-", title).lower()


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', form=form,
                                   message='passwords are not equal')
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', form=form,
                                   message=('User with this '
                                            'email already exists'))
        user = User()
        user.name = form.name.data
        user.email = form.email.data
        user.slug = slugify(user.name)
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User)
        user = user.filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect('/')
        return render_template('login.html',
                               message="Wrong login or password",
                               form=form)
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/')
def main_page():
    return render_template('main_page.html')


@app.route('/users/<user_slug>')
def profile(user_slug):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if user:
        return render_template('profile.html', user=user)
    return abort(404)


@app.route('/users/<user_slug>/projects/<project_slug>')
def project(user_slug, project_slug):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)
    return render_template('project.html', project=project)


@app.route('/users/<user_slug>/projects/<project_slug>/delete')
def delete_project(user_slug, project_slug):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)
    if current_user.id != project.leader_id:
        return abort(403)
    db_sess.delete(project)
    db_sess.commit()
    return redirect('/users/<user_slug>/projects')


@app.route('/users/<user_slug>/projects/<project_slug>/chat',
           methods=['GET', 'POST'])
def project_chat(user_slug, project_slug):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)
    return render_template('chat.html', project=project)


@app.route('/create_project', methods=['GET', 'POST'])
def create_project():
    if not current_user.is_authenticated:
        return abort(403)
    form = ProjectForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        project = Project()
        project.title = form.title.data
        project.description = form.description.data
        if db_sess.query(Project).filter(Project.slug == slugify(project.title)).first():
            pass  # write a auto generation of slug
        else:
            project.slug = slugify(project.title)
        db_sess.add(project)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', form=form)



def main():
    db_session.global_init("db/data.db")
    app.run(port=8080, host='127.0.0.1')


if __name__ == '__main__':
    main()

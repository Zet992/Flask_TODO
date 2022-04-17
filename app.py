import re

from flask import Flask, render_template, url_for, request, redirect
from flask import abort, make_response, jsonify

from flask_login import LoginManager, login_required, login_user
from flask_login import logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, EmailField
from wtforms import BooleanField, DateTimeField, TextAreaField
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
    submit = SubmitField('Submit')


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    is_finished = BooleanField('Is it finished?')
    submit = SubmitField('Submit')


class MessageForm(FlaskForm):
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Submit')


def slugify(title):
    pattern = r"[^\w+]"
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
        if db_sess.query(User).filter(User.slug == slugify(user.name)).first():
            pass  # write an auto generation of slug
        else:
            user.slug = slugify(user.name)
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
    db_sess = db_session.create_session()
    projects = db_sess.query(Project).all()
    return render_template('main_page.html', projects=projects)


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
    return redirect(f'/users/{user_slug}')


@app.route('/users/<user_slug>/projects/<project_slug>/create_task',
           methods=['GET', 'POST'])
def create_task(user_slug, project_slug):
    if not current_user.is_authenticated:
        return abort(403)
    db_sess = db_session.create_session()
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if project.leader != current_user:
        return abort(403)
    form = TaskForm()
    if form.validate_on_submit():
        task = Task()
        task.title = form.title.data
        task.description = form.description.data
        task.is_finished = form.is_finished.data
        task.project_id = project.id
        db_sess.add(task)
        db_sess.commit()
        return redirect(f'/users/{user_slug}/projects/{project_slug}')
    return render_template('create_task.html', form=form)


@app.route('/users/<user_slug>/projects/<project_slug>/tasks/<int:task_id>')
def delete_task(user_slug, project_slug, task_id):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)
    if current_user.id != project.leader_id:
        return abort(403)
    task = db_sess.query(Task).get(task_id)
    if not task:
        return abort(404)
    db_sess.delete(task)
    db_sess.commit()
    return redirect(f'/users/{user_slug}/projects/{project_slug}')


@app.route('/users/<user_slug>/projects/<project_slug>/chat',
           methods=['GET', 'POST'])
def project_chat(user_slug, project_slug):
    form = MessageForm()
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)

    if form.validate_on_submit() and current_user.is_authenticated:
        message = Message()
        message.author_id = current_user.id
        message.project_id = project.id
        message.body = form.body.data
        db_sess.add(message)
        db_sess.commit()

    return render_template('chat.html', project=project, form=form)


@app.route('/users/<user_slug>/projects/<project_slug>/messages/<int:message_id>')
def delete_message(user_slug, project_slug, message_id):
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.slug == user_slug).first()
    if not user:
        return abort(404)
    project = db_sess.query(Project).filter(Project.slug == project_slug).first()
    if not project or project.leader_id != user.id:
        return abort(404)
    if current_user.id != project.leader_id:
        return abort(403)
    message = db_sess.query(Message).get(message_id)
    if not message:
        return abort(404)
    db_sess.delete(message)
    db_sess.commit()
    return redirect(f'/users/{user_slug}/projects/{project_slug}')


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
        project.leader_id = current_user.id
        if db_sess.query(Project).filter(Project.slug == slugify(project.title)).first():
            pass  # write an auto generation of slug
        else:
            project.slug = slugify(project.title)
        project.members.append(current_user)
        obj_sess = db_sess.object_session(project)
        if obj_sess:
            obj_sess.add(project)
            obj_sess.commit()
        else:
            db_sess.add(project)
            db_sess.commit()
        return redirect(f'/users/{current_user.slug}')
    return render_template('create_project.html', form=form)


def main():
    db_session.global_init("db/data.db")
    app.run(port=8080, host='127.0.0.1')


if __name__ == '__main__':
    main()

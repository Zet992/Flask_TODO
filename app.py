from flask import Flask


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'special_secret_key'


def main():
    db_session.global_init("db/data.db")
    app.run(port=8080, host='127.0.0.1')


if __name__ == '__main__':
    main()

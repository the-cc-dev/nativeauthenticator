import bcrypt
from datetime import datetime
from jupyterhub.orm import User
from jupyterhub.auth import Authenticator

from sqlalchemy import inspect
from sqlalchemy.orm import relationship
from tornado import gen
from traitlets import Integer

from .handlers import (AuthorizationHandler, ChangeAuthorizationHandler,
                       SignUpHandler)
from .orm import UserInfo


class NativeAuthenticator(Authenticator):

    allowed_failed_logins = Integer(
        config=True,
        default=0,
        help="""Configures the number of failed attempts a user can have
                before being blocked."""
    )
    secs_before_next_try = Integer(
        config=True,
        default=600,
        help="""Configures the number of seconds a user has to wait
                after being blocked. Default is 600."""
    )

    def __init__(self, add_new_table=True, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.login_attempts = dict()
        if add_new_table:
            self.add_new_table()

    def add_new_table(self):
        inspector = inspect(self.db.bind)
        if 'users_info' not in inspector.get_table_names():
            User.info = relationship(UserInfo, backref='users')
            UserInfo.__table__.create(self.db.bind)

    def exceed_atempts_of_login(self, username):
        now = datetime.now()
        login_attempts = self.login_attempts.get(username)
        if not login_attempts:
            self.login_attempts[username] = {'count': 1, 'time': now}
            return False

        time_last_attempt = now - login_attempts['time']
        if time_last_attempt.seconds > self.secs_before_next_try:
            self.login_attempts.pop(username)
            return False

        if login_attempts['count'] < self.allowed_failed_logins:
            self.login_attempts[username]['count'] += 1
            self.login_attempts[username]['time'] = now
            return False

        return True

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data['username']
        password = data['password']

        user = UserInfo.find(self.db, username)
        if not user:
            return

        if self.allowed_failed_logins:
            if self.exceed_atempts_of_login(username):
                return

        if user.is_authorized and user.is_valid_password(password):
            return username

    def get_or_create_user(self, username, password):
        user = User.find(self.db, username)
        if not user:
            user = User(name=username, admin=False)
            self.db.add(user)

        encoded_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        infos = {'user': user, 'username': username, 'password': encoded_pw}
        if username in self.admin_users:
            infos.update({'is_authorized': True})

        user_info = UserInfo(**infos)
        self.db.add(user_info)
        return user

    def get_handlers(self, app):
        native_handlers = [
            (r'/signup', SignUpHandler),
            (r'/authorize', AuthorizationHandler),
            (r'/authorize/([^/]*)', ChangeAuthorizationHandler)
        ]
        return super().get_handlers(app) + native_handlers

import bcrypt
import os
from jupyterhub.auth import Authenticator

from sqlalchemy import inspect
from tornado import gen
from traitlets import Bool, Integer

from .handlers import (AuthorizationHandler, ChangeAuthorizationHandler,
                       SignUpHandler)
from .orm import UserInfo


class NativeAuthenticator(Authenticator):

    COMMON_PASSWORDS = None
    check_common_password = Bool(
        config=True,
        default=False,
        help="""Creates a verification of password strength
        when a new user makes signup"""
    )
    minimum_password_length = Integer(
        config=True,
        default=1,
        help="""Check if the length of the password is at least this size on
        signup"""
    )

    def __init__(self, add_new_table=True, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if add_new_table:
            self.add_new_table()

    def add_new_table(self):
        inspector = inspect(self.db.bind)
        if 'users_info' not in inspector.get_table_names():
            UserInfo.__table__.create(self.db.bind)

    @gen.coroutine
    def authenticate(self, handler, data):
        user = UserInfo.find(self.db, data['username'])
        if not user:
            return
        if user.is_authorized and user.is_valid_password(data['password']):
            return data['username']

    def is_password_common(self, password):
        common_credentials_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'common-credentials.txt'
        )
        if not self.COMMON_PASSWORDS:
            with open(common_credentials_file) as f:
                self.COMMON_PASSWORDS = f.read().splitlines()
        return password in self.COMMON_PASSWORDS

    def is_password_strong(self, password):
        checks = [len(password) > self.minimum_password_length]

        if self.check_common_password:
            checks.append(not self.is_password_common(password))

        return all(checks)

    def get_or_create_user(self, username, pw):
        user = UserInfo.find(self.db, username)
        if user:
            return user

        if not self.is_password_strong(pw):
            return

        encoded_pw = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        infos = {'username': username, 'password': encoded_pw}
        if username in self.admin_users:
            infos.update({'is_authorized': True})

        user_info = UserInfo(**infos)
        self.db.add(user_info)
        return user_info

    def get_handlers(self, app):
        native_handlers = [
            (r'/signup', SignUpHandler),
            (r'/authorize', AuthorizationHandler),
            (r'/authorize/([^/]*)', ChangeAuthorizationHandler)
        ]
        return super().get_handlers(app) + native_handlers

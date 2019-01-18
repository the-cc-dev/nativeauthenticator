import pytest
import time
from jupyterhub.orm import User
from jupyterhub.tests.mocking import MockHub

from nativeauthenticator import NativeAuthenticator
from ..orm import UserInfo


@pytest.fixture
def tmpcwd(tmpdir):
    tmpdir.chdir()


@pytest.fixture
def app():
    hub = MockHub()
    hub.init_db()
    return hub


# use pytest-asyncio
pytestmark = pytest.mark.asyncio
# run each test in a temporary working directory
pytestmark = pytestmark(pytest.mark.usefixtures("tmpcwd"))


async def test_auth_get_or_create(tmpcwd, app):
    '''Test if method get_or_create_user creates a new user'''
    auth = NativeAuthenticator(db=app.db)
    user = auth.get_or_create_user('John Snow', 'password')
    main_user = User.find(app.db, 'John Snow')
    user_info = UserInfo.find(app.db, 'John Snow')
    assert user == main_user
    assert user_info.username == 'John Snow'


async def test_failed_authentication_user_doesnt_exist(tmpcwd, app):
    '''Test if authentication fails with a unexistent user'''
    auth = NativeAuthenticator(db=app.db)
    response = await auth.authenticate(app, {'username': 'name',
                                             'password': '123'})
    assert not response


async def test_failed_authentication_wrong_password(tmpcwd, app):
    '''Test if authentication fails with a wrong password'''
    auth = NativeAuthenticator(db=app.db)
    auth.get_or_create_user('John Snow', 'password')
    response = await auth.authenticate(app, {'username': 'John Snow',
                                             'password': '123'})
    assert not response


async def test_failed_authentication_not_authorized(tmpcwd, app):
    '''Test if authentication fails with a wrong password'''
    auth = NativeAuthenticator(db=app.db)
    auth.get_or_create_user('John Snow', 'password')
    response = await auth.authenticate(app, {'username': 'John Snow',
                                             'password': 'password'})
    assert not response


async def test_succeded_authentication(tmpcwd, app):
    '''Test a successfull authentication'''
    auth = NativeAuthenticator(db=app.db)
    user = auth.get_or_create_user('John Snow', 'password')
    UserInfo.change_authorization(app.db, 'John Snow')
    response = await auth.authenticate(app, {'username': 'John Snow',
                                             'password': 'password'})
    assert response == user.name


async def test_handlers(app):
    '''Test if all handlers are available on the Authenticator'''
    auth = NativeAuthenticator(db=app.db)
    handlers = auth.get_handlers(app)
    assert handlers[1][0] == '/signup'
    assert handlers[2][0] == '/authorize'


async def test_exceed_atemps_of_login(tmpcwd, app):
    auth = NativeAuthenticator(db=app.db)
    username = 'John Snow'
    auth.get_or_create_user(username, 'password')

    assert not auth.exceed_atempts_of_login(username)
    assert not auth.exceed_atempts_of_login(username)
    assert not auth.exceed_atempts_of_login(username)
    assert auth.exceed_atempts_of_login(username)
    time.sleep(65)
    assert not auth.exceed_atempts_of_login(username)

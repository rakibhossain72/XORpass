import pytest
import mongomock
from unittest.mock import patch
import app as flask_app
import databases

@pytest.fixture
def mock_mongo():
    mock_client = mongomock.MongoClient()
    mongo_obj = databases.Mongo("mongodb://localhost:27017")
    mongo_obj.client = mock_client
    mongo_obj.db = mock_client["xorpass"]
    return mongo_obj

@pytest.fixture
def client(mock_mongo):
    flask_app.app.config['TESTING'] = True
    flask_app.app.config['WTF_CSRF_ENABLED'] = False

    with patch('app.client', mock_mongo):
        with flask_app.app.test_client() as test_client:
            yield test_client

def test_signup_and_login_flow(client, mock_mongo):
    # Test Signup
    response = client.post('/signup', data={
        'email': 'user1@example.com',
        'password': 'Password123!',
        'confirm-password': 'Password123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Vault Overview' in response.data or b'Welcome' in response.data

    user = mock_mongo.get_user('user1@example.com')
    assert user is not None
    assert user['email'] == 'user1@example.com'

    # Test Logout
    client.get('/logout')

    # Test Login
    response = client.post('/login', data={
        'email': 'user1@example.com',
        'password': 'Password123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Vault Overview' in response.data

def test_add_password_and_authorization(client, mock_mongo):
    # Register user 1
    client.post('/signup', data={
        'email': 'user1@example.com',
        'password': 'Password123!',
        'confirm-password': 'Password123!'
    })

    # Add password entry for user 1
    res = client.post('/add', data={
        'website': 'github.com',
        'email': 'mydev@github.com',
        'password': 'SecretGithubPassword123!'
    }, follow_redirects=True)
    assert res.status_code == 200

    entries = mock_mongo.get_data('user1@example.com')
    assert len(entries) == 1
    doc_id = str(entries[0]['_id'])

    # Logout user 1
    client.get('/logout')

    # Register user 2
    client.post('/signup', data={
        'email': 'user2@example.com',
        'password': 'Password123!',
        'confirm-password': 'Password123!'
    })

    # User 2 attempts to decrypt user 1's entry (Unauthorized)
    res_dec = client.get(f'/decrypt/{doc_id}', follow_redirects=True)
    assert b'Unauthorized access' in res_dec.data or b'Vault Overview' in res_dec.data

    # User 2 attempts to delete user 1's entry (Unauthorized)
    res_del = client.post('/delete', data={'id': doc_id}, follow_redirects=True)
    assert b'Unauthorized access' in res_del.data

def test_password_generator_endpoint(client):
    res = client.get('/generate-password?length=20')
    assert res.status_code == 200
    json_data = res.get_json()
    assert 'password' in json_data
    assert len(json_data['password']) == 20

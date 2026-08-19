import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.main import app
from app.db.database import Base, get_db
import app.db.crud as crud
import app.core.cache as cache

# Setup in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await cache.cache_clear()

@pytest.mark.asyncio
async def test_signup_and_login_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Signup
        response = await client.post('/signup', data={
            'email': 'user1@example.com',
            'password': 'Password123!',
            'confirm-password': 'Password123!'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Vault Overview" in response.text or "Welcome" in response.text or "Add New Password" in response.text

        # Verify in DB
        async with TestingSessionLocal() as session:
            user = await crud.get_user_by_email(session, 'user1@example.com')
            assert user is not None
            assert user.email == 'user1@example.com'

        # Logout
        await client.get('/logout')

        # Login
        response = await client.post('/login', data={
            'email': 'user1@example.com',
            'password': 'Password123!'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert "Vault Overview" in response.text or "Add New Password" in response.text

@pytest.mark.asyncio
async def test_add_password_and_authorization():
    transport1 = ASGITransport(app=app)
    async with AsyncClient(transport=transport1, base_url="http://test") as client1:
        # Register user 1
        await client1.post('/signup', data={
            'email': 'user1@example.com',
            'password': 'Password123!',
            'confirm-password': 'Password123!'
        })

        # Add password entry for user 1
        res = await client1.post('/add', data={
            'website': 'github.com',
            'email': 'mydev@github.com',
            'password': 'SecretGithubPassword123!'
        }, follow_redirects=True)
        assert res.status_code == 200

        async with TestingSessionLocal() as session:
            entries = await crud.get_password_entries_by_owner(session, 'user1@example.com')
            assert len(entries) == 1
            doc_id = entries[0].id

        # Logout user 1
        await client1.get('/logout')

    # Client for User 2
    transport2 = ASGITransport(app=app)
    async with AsyncClient(transport=transport2, base_url="http://test") as client2:
        # Register user 2
        await client2.post('/signup', data={
            'email': 'user2@example.com',
            'password': 'Password123!',
            'confirm-password': 'Password123!'
        })

        # User 2 attempts to decrypt user 1's entry (Unauthorized)
        res_dec = await client2.get(f'/decrypt/{doc_id}', follow_redirects=True)
        assert 'Unauthorized access' in res_dec.text or 'Vault Overview' in res_dec.text

        # User 2 attempts to delete user 1's entry (Unauthorized)
        res_del = await client2.post('/delete', data={'id': doc_id}, follow_redirects=True)
        assert 'Unauthorized access' in res_del.text or 'Vault Overview' in res_del.text

@pytest.mark.asyncio
async def test_password_generator_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get('/generate-password?length=20')
        assert res.status_code == 200
        json_data = res.json()
        assert 'password' in json_data
        assert len(json_data['password']) == 20

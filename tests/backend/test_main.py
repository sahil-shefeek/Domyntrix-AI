import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from contextlib import asynccontextmanager

import numpy as np
import fakeredis.aioredis
from httpx import AsyncClient, ASGITransport
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine

import main
from main import app, get_session
from models import ScanRecord

# --- Fixtures ---


@pytest.fixture(name="mock_redis")
async def mock_redis_fixture():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    with patch("main.redis_client", redis):
        yield redis
    await redis.flushall()


@pytest.fixture(name="db_session")
async def db_session_fixture():
    # Use in-memory SQLite for tests
    sqlite_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(sqlite_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as session:
        # Override dependency
        async def override_get_session():
            yield session

        app.dependency_overrides[get_session] = override_get_session
        yield session
        app.dependency_overrides.clear()

    await engine.dispose()


@pytest.fixture(name="mock_interpreter")
def mock_interpreter_fixture():
    mock_ctx = AsyncMock()
    # Mocking the interpreter structure
    mock_interpreter_obj = MagicMock()
    mock_interpreter_obj.get_tensor.return_value = np.array([[0]], dtype=np.float32)

    mock_data = {
        "interpreter": mock_interpreter_obj,
        "input_details": [{"index": 0}],
        "output_details": [{"index": 0}],
    }

    mock_ctx.__aenter__.return_value = mock_data

    with patch("main.acquire_interpreter", return_value=mock_ctx):
        yield mock_ctx


@pytest.fixture(name="mock_features")
def mock_features_fixture():
    # google.com benign feature array from MADONNA paper Table 8
    benign_features = [10, 4, 2, 11322, 4, 5, 0, 0, 2.6464, 1, 0.93, 1, 353]
    with patch(
        "feature_extractions.extract_features", AsyncMock(return_value=benign_features)
    ) as mock:
        yield mock


@pytest.fixture(name="client")
async def client_fixture(mock_redis, db_session, mock_interpreter, mock_features):
    # Ensure redis_client is set to mock_redis
    main.redis_client = mock_redis

    # Bypass lifespan by patching it with a no-op async context manager
    @asynccontextmanager
    async def noop_lifespan(app):
        yield

    with patch("main.lifespan", noop_lifespan):
        # Set raise_app_exceptions=False to get 500 responses instead of bubbling up
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


# --- Tests ---


class TestTestUrlEndpoint:
    @pytest.mark.asyncio
    async def test_happy_path_model_result(self, client):
        with patch("main.is_whitelisted", AsyncMock(return_value=False)):
            response = await client.post(
                "/test_url", json={"url": "http://chromnius.download/browser2"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["mal_status"] in [0, 1]
            assert "length" in data["features"]
            assert len(data["explanations"]) > 0
            assert data["source"] == "model"
            assert data["whitelisted"] is False

    @pytest.mark.asyncio
    async def test_whitelist_short_circuit(self, client, mock_features):
        with patch("main.is_whitelisted", AsyncMock(return_value=True)):
            response = await client.post(
                "/test_url", json={"url": "http://any-url.com"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["source"] == "whitelist"
            assert data["features"] == {}
            assert data["explanations"] == []
            assert data["mal_status"] == 0
            mock_features.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_cache_hit(self, client, mock_redis):
        cached_payload = {
            "mal_status": 0,
            "inference_time_ms": 1.0,
            "features": {"length": 10},
            "explanations": ["Benign"],
            "whitelisted": False,
            "source": "model",
        }
        await mock_redis.set("google.com", json.dumps(cached_payload), ex=86400)

        response = await client.post("/test_url", json={"url": "http://google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["cached"] is True
        assert data["mal_status"] == 0

    @pytest.mark.asyncio
    async def test_missing_url_key(self, client):
        # The endpoint does data["url"] which raises KeyError.
        # With raise_app_exceptions=False, it should return 500.
        response = await client.post("/test_url", json={})
        assert response.status_code == 500


class TestWhitelistEndpoints:
    @pytest.mark.asyncio
    async def test_add_valid_domain(self, client):
        response = await client.post("/whitelist", json={"domain": "example.com"})
        assert response.status_code == 201
        assert response.json()["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_add_duplicate_domain(self, client):
        await client.post("/whitelist", json={"domain": "example.com"})
        response = await client.post("/whitelist", json={"domain": "example.com"})
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_add_invalid_domain(self, client):
        response = await client.post("/whitelist", json={"domain": "notadomain"})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_remove_existing_domain(self, client):
        await client.post("/whitelist", json={"domain": "example.com"})
        response = await client.delete("/whitelist/example.com")
        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_remove_non_existent_domain(self, client):
        response = await client.delete("/whitelist/doesnotexist.com")
        assert response.status_code == 404


class TestBlacklistEndpoints:
    @pytest.mark.asyncio
    async def test_add_valid_domain(self, client):
        response = await client.post("/blacklist", json={"domain": "malicious.com"})
        assert response.status_code == 201
        assert response.json()["domain"] == "malicious.com"

    @pytest.mark.asyncio
    async def test_add_duplicate_domain(self, client):
        await client.post("/blacklist", json={"domain": "malicious.com"})
        response = await client.post("/blacklist", json={"domain": "malicious.com"})
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_add_invalid_domain(self, client):
        response = await client.post("/blacklist", json={"domain": "notadomain"})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_remove_existing_domain(self, client):
        await client.post("/blacklist", json={"domain": "malicious.com"})
        response = await client.delete("/blacklist/malicious.com")
        assert response.status_code == 200
        assert response.json()["domain"] == "malicious.com"

    @pytest.mark.asyncio
    async def test_remove_non_existent_domain(self, client):
        response = await client.delete("/blacklist/doesnotexist.com")
        assert response.status_code == 404


class TestScansEndpoint:
    @pytest.mark.asyncio
    async def test_empty_db(self, client):
        response = await client.get("/scans")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["scans"] == []

    @pytest.mark.asyncio
    async def test_pagination(self, client, db_session):
        # Insert 3 records directly
        records = [
            ScanRecord(domain="a.com", malicious_status=0, inference_time_ms=1.0),
            ScanRecord(domain="b.com", malicious_status=1, inference_time_ms=2.0),
            ScanRecord(domain="c.com", malicious_status=0, inference_time_ms=3.0),
        ]
        for r in records:
            db_session.add(r)
        await db_session.commit()

        response = await client.get("/scans?page=1&page_size=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data["scans"]) == 2
        assert data["total"] == 3


class TestStatsEndpoint:
    @pytest.mark.asyncio
    async def test_empty_db(self, client):
        response = await client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "total_malicious" in data
        assert "total_benign" in data
        assert "avg_inference_time_ms" in data
        assert "whitelist_hits" in data
        assert "trend" in data

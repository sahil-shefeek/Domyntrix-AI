import pytest
import fakeredis.aioredis
from unittest.mock import patch, MagicMock
import io
import zipfile
import httpx
from redis.exceptions import ConnectionError

from whitelist_engine import (
    load_india_seed_list,
    load_tranco_list,
    load_umbrella_list,
    is_whitelisted,
    INDIA_SEED_DOMAINS,
    REDIS_WHITELIST_KEY,
    REDIS_UMBRELLA_KEY,
    REDIS_INDIA_KEY,
    REDIS_USER_WHITELIST_KEY,
    REDIS_USER_BLACKLIST_KEY
)

@pytest.fixture
async def fake_redis():
    """Provides a fresh FakeRedis instance pre-populated with India seed list."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    await load_india_seed_list(client)
    yield client
    await client.flushall()

@pytest.mark.asyncio
class TestIsWhitelisted:
    async def test_unknown_domain(self, fake_redis):
        assert await is_whitelisted("unknown-domain-test-123.com", fake_redis) is False

    async def test_india_seed_hit(self, fake_redis):
        # "kerala.gov.in" is in INDIA_SEED_DOMAINS
        assert await is_whitelisted("kerala.gov.in", fake_redis) is True

    async def test_subdomain_resolution(self, fake_redis):
        # "mail.kerala.gov.in" -> "kerala.gov.in"
        assert await is_whitelisted("mail.kerala.gov.in", fake_redis) is True

    async def test_tranco_hit(self, fake_redis):
        await fake_redis.sadd(REDIS_WHITELIST_KEY, "google.com")
        assert await is_whitelisted("google.com", fake_redis) is True

    async def test_umbrella_hit(self, fake_redis):
        await fake_redis.sadd(REDIS_UMBRELLA_KEY, "facebook.com")
        assert await is_whitelisted("facebook.com", fake_redis) is True

    async def test_user_whitelist_hit(self, fake_redis):
        await fake_redis.sadd(REDIS_USER_WHITELIST_KEY, "my-safe-site.com")
        assert await is_whitelisted("my-safe-site.com", fake_redis) is True

    async def test_blacklist_overrides_whitelist(self, fake_redis):
        # Add to both Tranco (whitelist) and User Blacklist
        await fake_redis.sadd(REDIS_WHITELIST_KEY, "google.com")
        await fake_redis.sadd(REDIS_USER_BLACKLIST_KEY, "google.com")
        # Blacklist must win
        assert await is_whitelisted("google.com", fake_redis) is False

    async def test_invalid_domain(self, fake_redis):
        assert await is_whitelisted("notadomain", fake_redis) is False

    async def test_redis_failure_graceful_fallback(self):
        # Mock pipeline to raise ConnectionError
        # Use a fresh client to avoid affecting other tests if patch fails
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        with patch.object(fakeredis.aioredis.FakeRedis, 'pipeline') as mock_pipe:
            mock_pipe.side_effect = ConnectionError("Mocked connection failure")
            # Fail-open: should return False
            assert await is_whitelisted("google.com", client) is False

@pytest.mark.asyncio
class TestLoadIndiaSeedList:
    async def test_load_india_seed_list_success(self):
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        res = await load_india_seed_list(client)
        assert res["status"] == "ok"
        assert res["domains_loaded"] == len(INDIA_SEED_DOMAINS)
        assert await client.sismember(REDIS_INDIA_KEY, "kerala.gov.in")

@pytest.mark.asyncio
class TestLoadExternalLists:
    def create_fake_zip_bytes(self, domains):
        """Helper to create a valid ZIP in memory containing top-1m.csv."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            content = "\n".join([f"{i+1},{domain}" for i, domain in enumerate(domains)])
            z.writestr("top-1m.csv", content)
        return buf.getvalue()

    async def test_load_tranco_list_success(self, fake_redis):
        fake_domains = [f"tranco{i}.com" for i in range(5)]
        zip_bytes = self.create_fake_zip_bytes(fake_domains)
        
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            res = await load_tranco_list(fake_redis)
            assert res["status"] == "ok"
            assert res["domains_loaded"] == 5
            # Verify Redis content
            assert await fake_redis.scard(REDIS_WHITELIST_KEY) == 5
            assert await fake_redis.sismember(REDIS_WHITELIST_KEY, "tranco0.com")
            # Verify TTL
            assert await fake_redis.ttl(REDIS_WHITELIST_KEY) > 0

    async def test_load_umbrella_list_success(self, fake_redis):
        fake_domains = [f"umbrella{i}.com" for i in range(5)]
        zip_bytes = self.create_fake_zip_bytes(fake_domains)
        
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            res = await load_umbrella_list(fake_redis)
            assert res["status"] == "ok"
            assert res["domains_loaded"] == 5
            # Verify Redis content
            assert await fake_redis.scard(REDIS_UMBRELLA_KEY) == 5
            assert await fake_redis.sismember(REDIS_UMBRELLA_KEY, "umbrella0.com")
            # Verify TTL
            assert await fake_redis.ttl(REDIS_UMBRELLA_KEY) > 0

    async def test_load_list_failure(self, fake_redis):
        with patch("httpx.AsyncClient.get", side_effect=httpx.RequestError("Mocked network error")):
            res = await load_tranco_list(fake_redis)
            assert res["status"] == "error"
            assert "Mocked network error" in res["message"]

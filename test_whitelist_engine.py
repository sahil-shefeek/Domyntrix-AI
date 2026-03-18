"""
Standalone verification script for whitelist_engine.py
Run with: uv run python test_whitelist_engine.py
Requires: Redis running on localhost:6379
"""
import asyncio
import logging
import redis.asyncio as redis
from whitelist_engine import load_tranco_list, is_whitelisted

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

async def main():
    r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    try:
        await r.ping()
        print("✅ Redis connection OK")
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return

    print("\n--- Test 1: Loading Tranco list ---")
    result = await load_tranco_list(r)
    print(f"Result: {result}")
    assert result["status"] == "ok", "Load failed"
    assert result["domains_loaded"] > 900_000, "Expected >900k domains"
    print("✅ Tranco list loaded successfully")

    print("\n--- Test 2: Known benign domain (google.com) ---")
    assert await is_whitelisted("google.com", r) == True
    print("✅ google.com → whitelisted")

    print("\n--- Test 3: Subdomain strips correctly (sub.google.com) ---")
    assert await is_whitelisted("sub.google.com", r) == True
    print("✅ sub.google.com → whitelisted (via registered domain)")

    print("\n--- Test 4: Random unknown domain ---")
    result = await is_whitelisted("definitelynotreal-xyzabc123.com", r)
    print(f"✅ unknown domain → {result} (expected False)")

    print("\n--- Test 5: Blacklist overrides whitelist ---")
    await r.sadd("blacklist:user", "google.com")
    assert await is_whitelisted("google.com", r) == False
    await r.srem("blacklist:user", "google.com")  # cleanup
    print("✅ Blacklist override works correctly")

    print("\n--- Test 6: Redis failure graceful fallback ---")
    broken_client = redis.Redis(host="localhost", port=9999, db=0)  # wrong port
    result = await is_whitelisted("google.com", broken_client)
    assert result == False
    print("✅ Redis failure returns False gracefully")

    await r.aclose()
    print("\n🎉 All tests passed.")

asyncio.run(main())

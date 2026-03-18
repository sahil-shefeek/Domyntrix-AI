"""
Standalone verification script for whitelist_engine.py
Run with: uv run python test_whitelist_engine.py
Requires: Redis running on localhost:6379
"""
import asyncio
import logging
import time
import redis.asyncio as redis
from whitelist_engine import (
    load_tranco_list, 
    load_umbrella_list, 
    load_india_seed_list, 
    is_whitelisted
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

async def main():
    r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    try:
        await r.ping()
        print("✅ Redis connection OK")
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return

    print("\n--- Test 1: Loading Whitelists Concurrently ---")
    results = await asyncio.gather(
        load_india_seed_list(r),
        load_tranco_list(r),
        load_umbrella_list(r)
    )
    for res in results:
        print(f"Loaded {res.get('key')}: {res.get('domains_loaded')} domains")
        assert res["status"] == "ok", f"Load failed for {res.get('key')}"
    
    india_count = results[0]["domains_loaded"]
    tranco_count = results[1]["domains_loaded"]
    umbrella_count = results[2]["domains_loaded"]
    
    assert india_count >= 50, f"Expected >50 India seed domains, got {india_count}"
    assert tranco_count > 900_000, f"Expected >900k Tranco domains, got {tranco_count}"
    assert umbrella_count > 900_000, f"Expected >900k Umbrella domains, got {umbrella_count}"
    print("✅ All whitelist sources loaded successfully")

    print("\n--- Test 2: Kerala government domain ---")
    assert await is_whitelisted("kerala.gov.in", r) == True
    print("✅ kerala.gov.in → whitelisted (India seed)")

    print("\n--- Test 3: Subdomain of seed domain ---")
    assert await is_whitelisted("mail.kerala.gov.in", r) == True
    print("✅ mail.kerala.gov.in → whitelisted via registered domain")

    print("\n--- Test 4: Malayalam news site ---")
    assert await is_whitelisted("mathrubhumi.com", r) == True
    print("✅ mathrubhumi.com → whitelisted (India seed)")

    print("\n--- Test 5: Umbrella list loaded verification ---")
    actual_umbrella_count = await r.scard("whitelist:umbrella")
    assert actual_umbrella_count > 900_000
    print(f"✅ Umbrella list verified in Redis: {actual_umbrella_count} domains")

    print("\n--- Test 6: Pipeline batch check (performance) ---")
    start = time.time()
    for _ in range(100):
        await is_whitelisted("google.com", r)
    elapsed = (time.time() - start) * 1000
    print(f"✅ 100 lookups completed in {elapsed:.1f}ms (pipeline batching)")

    print("\n--- Test 7: Blacklist overrides whitelist ---")
    await r.sadd("blacklist:user", "google.com")
    assert await is_whitelisted("google.com", r) == False
    await r.srem("blacklist:user", "google.com")  # cleanup
    print("✅ Blacklist override works correctly")

    print("\n--- Test 8: Redis failure graceful fallback ---")
    broken_client = redis.Redis(host="localhost", port=9999, db=0)  # wrong port
    result = await is_whitelisted("google.com", broken_client)
    assert result == False
    print("✅ Redis failure returns False gracefully")

    await r.aclose()
    print("\n🎉 All tests passed.")

if __name__ == "__main__":
    asyncio.run(main())

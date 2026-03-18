import io
import zipfile
import logging
import asyncio
import os

import httpx
import tldextract

logger = logging.getLogger(__name__)

TRANCO_URL = os.environ.get("TRANCO_URL", "https://tranco-list.eu/top-1m.csv.zip")
REDIS_WHITELIST_KEY = os.environ.get("REDIS_WHITELIST_KEY", "whitelist:tranco")
REDIS_USER_WHITELIST_KEY = os.environ.get("REDIS_USER_WHITELIST_KEY", "whitelist:user")
REDIS_USER_BLACKLIST_KEY = os.environ.get("REDIS_USER_BLACKLIST_KEY", "blacklist:user")
TRANCO_DOWNLOAD_TIMEOUT_SECONDS = int(os.environ.get("TRANCO_DOWNLOAD_TIMEOUT_SECONDS", "60"))

async def load_tranco_list(redis_client) -> dict:
    try:
        logger.info("Starting Tranco Top 1 Million list download from %s...", TRANCO_URL)
        async with httpx.AsyncClient(timeout=TRANCO_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = await client.get(TRANCO_URL)
            response.raise_for_status()
            
        logger.info("Download complete. Extracting CSV from ZIP in-memory...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_filename = "top-1m.csv"
            if csv_filename not in z.namelist():
                csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                content = f.read().decode('utf-8')
        
        logger.info("Parsing CSV and loading domains into Redis...")
        lines = content.strip().split('\n')
        
        total_domains = 0
        chunk_size = 10000
        
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i:i + chunk_size]
            domains_to_add = []
            for line in chunk:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    domains_to_add.append(parts[1])
            
            if domains_to_add:
                async with redis_client.pipeline() as pipe:
                    for domain in domains_to_add:
                        pipe.sadd(REDIS_WHITELIST_KEY, domain)
                    await pipe.execute()
                total_domains += len(domains_to_add)
            
            if total_domains % 100000 == 0:
                logger.info("Processed %d domains so far...", total_domains)
                
        # Set TTL of 8 days (691200 seconds)
        await redis_client.expire(REDIS_WHITELIST_KEY, 691200)
        
        logger.info("Completed loading %d domains. Key TTL set to 8 days.", total_domains)
        return {"status": "ok", "domains_loaded": total_domains, "key": REDIS_WHITELIST_KEY}
        
    except Exception as e:
        logger.error("Failed to load Tranco list: %s", str(e))
        return {"status": "error", "message": str(e)}

async def is_whitelisted(domain: str, redis_client) -> bool:
    try:
        extract_result = tldextract.extract(domain)
        registered_domain = extract_result.registered_domain
        
        if not registered_domain:
            return False
            
        # 1. Check blacklist first
        if await redis_client.sismember(REDIS_USER_BLACKLIST_KEY, registered_domain):
            return False
            
        # 2. Check user whitelist
        if await redis_client.sismember(REDIS_USER_WHITELIST_KEY, registered_domain):
            return True
            
        # 3. Check Tranco whitelist
        if await redis_client.sismember(REDIS_WHITELIST_KEY, registered_domain):
            return True
            
        return False
        
    except Exception as e:
        logger.warning("Redis error during whitelist check: %s", str(e))
        # Fail open: don't block scans if Redis is down
        return False

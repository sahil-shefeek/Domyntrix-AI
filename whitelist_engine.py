import io
import zipfile
import logging
import os

import httpx
import tldextract

logger = logging.getLogger(__name__)

TRANCO_URL = os.environ.get("TRANCO_URL", "https://tranco-list.eu/top-1m.csv.zip")
UMBRELLA_URL = os.environ.get("UMBRELLA_URL", "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip")

REDIS_WHITELIST_KEY = os.environ.get("REDIS_WHITELIST_KEY", "whitelist:tranco")
REDIS_UMBRELLA_KEY = os.environ.get("REDIS_UMBRELLA_KEY", "whitelist:umbrella")
REDIS_INDIA_KEY = os.environ.get("REDIS_INDIA_KEY", "whitelist:india")
REDIS_USER_WHITELIST_KEY = os.environ.get("REDIS_USER_WHITELIST_KEY", "whitelist:user")
REDIS_USER_BLACKLIST_KEY = os.environ.get("REDIS_USER_BLACKLIST_KEY", "blacklist:user")

TRANCO_DOWNLOAD_TIMEOUT_SECONDS = int(os.environ.get("TRANCO_DOWNLOAD_TIMEOUT_SECONDS", "60"))
UMBRELLA_DOWNLOAD_TIMEOUT_SECONDS = int(os.environ.get("UMBRELLA_DOWNLOAD_TIMEOUT_SECONDS", "60"))

# Static curated list of high-confidence Indian/Kerala domains
INDIA_SEED_DOMAINS = [
    # Kerala Government
    "kerala.gov.in", "keralapolice.gov.in", "keralauniversity.ac.in", "mgu.ac.in", "cusat.ac.in", 
    "nitc.ac.in", "iiitmk.ac.in", "dhsekerala.gov.in",
    
    # Indian Central Government
    "india.gov.in", "incometax.gov.in", "uidai.gov.in", "irctc.co.in", "digilocker.gov.in", 
    "cowin.gov.in", "passportindia.gov.in", "mha.gov.in",
    
    # Indian Banking & Finance
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com", 
    "phonepe.com", "razorpay.com", "upi.npci.org.in", "pnbindia.in", "bankofbaroda.in",
    
    # Indian Telecom
    "jio.com", "airtel.in", "bsnl.co.in", "vi.in", "mtnl.net.in",
    
    # Indian News & Media
    "thehindu.com", "ndtv.com", "timesofindia.com", "manoramaonline.com", "mathrubhumi.com", 
    "asianetnews.com", "keralakaumudi.com", "deepika.com", "deshabhimani.com", "madhyamam.com",
    
    # Indian E-commerce & Tech
    "flipkart.com", "amazon.in", "myntra.com", "swiggy.com", "zomato.com", 
    "ola.com", "meesho.com", "bigbasket.com", "nykaa.com", "tata.com",
    
    # Indian Education & IT
    "iitm.ac.in", "iimb.ac.in", "nit.ac.in", "amrita.edu", "tcs.com", 
    "infosys.com", "wipro.com", "hcltech.com", "cognizant.com"
]

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
                logger.info("Processed %d domains so far from Tranco...", total_domains)
                
        # Set TTL of 8 days (691200 seconds)
        await redis_client.expire(REDIS_WHITELIST_KEY, 691200)
        
        logger.info("Completed loading %d Tranco domains. Key TTL set to 8 days.", total_domains)
        return {"status": "ok", "domains_loaded": total_domains, "key": REDIS_WHITELIST_KEY}
        
    except Exception as e:
        logger.error("Failed to load Tranco list: %s", str(e))
        return {"status": "error", "message": str(e)}

async def load_umbrella_list(redis_client) -> dict:
    try:
        logger.info("Starting Cisco Umbrella Top 1 Million list download from %s...", UMBRELLA_URL)
        async with httpx.AsyncClient(timeout=UMBRELLA_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = await client.get(UMBRELLA_URL)
            response.raise_for_status()
            
        logger.info("Download complete. Extracting CSV from ZIP in-memory...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            # Umbrella zip typically contains top-1m.csv
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
                        pipe.sadd(REDIS_UMBRELLA_KEY, domain)
                    await pipe.execute()
                total_domains += len(domains_to_add)
            
            if total_domains % 100000 == 0:
                logger.info("Processed %d domains so far from Umbrella...", total_domains)
                
        # Set TTL of 8 days (691200 seconds)
        await redis_client.expire(REDIS_UMBRELLA_KEY, 691200)
        
        logger.info("Completed loading %d Umbrella domains. Key TTL set to 8 days.", total_domains)
        return {"status": "ok", "domains_loaded": total_domains, "key": REDIS_UMBRELLA_KEY}
        
    except Exception as e:
        logger.error("Failed to load Umbrella list: %s", str(e))
        return {"status": "error", "message": str(e)}

async def load_india_seed_list(redis_client) -> dict:
    try:
        logger.info("Loading India/Kerala seed list into Redis...")
        async with redis_client.pipeline() as pipe:
            for domain in INDIA_SEED_DOMAINS:
                pipe.sadd(REDIS_INDIA_KEY, domain)
            await pipe.execute()
        
        logger.info("Successfully loaded %d India seed domains into Redis.", len(INDIA_SEED_DOMAINS))
        return {"status": "ok", "domains_loaded": len(INDIA_SEED_DOMAINS), "key": REDIS_INDIA_KEY}
    except Exception as e:
        logger.warning("Failed to load India seed list: %s", str(e))
        return {"status": "error", "message": str(e)}

async def is_whitelisted(domain: str, redis_client) -> bool:
    try:
        extract_result = tldextract.extract(domain)
        registered_domain = extract_result.registered_domain
        
        if not registered_domain:
            return False
            
        # Batch all checks into a single pipeline for performance
        async with redis_client.pipeline() as pipe:
            pipe.sismember(REDIS_USER_BLACKLIST_KEY, registered_domain)
            pipe.sismember(REDIS_USER_WHITELIST_KEY, registered_domain)
            pipe.sismember(REDIS_INDIA_KEY, registered_domain)
            pipe.sismember(REDIS_WHITELIST_KEY, registered_domain)
            pipe.sismember(REDIS_UMBRELLA_KEY, registered_domain)
            results = await pipe.execute()
            
        # Results mapping: 0=blacklist, 1=user_wl, 2=india, 3=tranco, 4=umbrella
        if results[0]: # Blacklist always wins
            return False
        if results[1]: # User whitelist
            return True
        if results[2]: # India seed list
            return True
        if results[3]: # Tranco list
            return True
        if results[4]: # Umbrella list
            return True
            
        return False
        
    except Exception as e:
        logger.warning("Redis error during whitelist check: %s", str(e))
        # Fail open: don't block scans if Redis is down
        return False

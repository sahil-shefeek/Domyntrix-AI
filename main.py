import time
import asyncio
import json
import os
import logging
from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import redis.asyncio as redis
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select, func
from pydantic import BaseModel
import tldextract

import feature_extractions
from database import get_session, engine
from models import ScanRecord, UserWhitelist, UserBlacklist
from ml_pool import init_pool, acquire_interpreter
from whitelist_engine import (
    is_whitelisted, 
    REDIS_USER_WHITELIST_KEY, 
    REDIS_USER_BLACKLIST_KEY, 
    load_tranco_list,
    load_umbrella_list,
    load_india_seed_list
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from xai_translator import translate

logging.basicConfig(level=logging.INFO)

class WhitelistRequest(BaseModel):
    domain: str
    note: str | None = None

class BlacklistRequest(BaseModel):
    domain: str
    note: str | None = None


redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_client = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)
    try:
        await redis_client.ping()
        print("INFO: Connected to Redis successfully.")
        
        try:
            async with AsyncSession(engine) as session:
                wl_result = await session.execute(select(UserWhitelist))
                for entry in wl_result.scalars().all():
                    await redis_client.sadd(REDIS_USER_WHITELIST_KEY, entry.domain)
                    
                bl_result = await session.execute(select(UserBlacklist))
                for entry in bl_result.scalars().all():
                    await redis_client.sadd(REDIS_USER_BLACKLIST_KEY, entry.domain)
            print("INFO: Hydrated Redis from database.")
        except Exception as e:
            print(f"WARNING: Failed to hydrate Redis from DB: {e}")
            
    except Exception as e:
        print(f"WARNING: Failed to connect to Redis during startup: {e}")

    await init_pool("lite_model_optimized_float16.tflite")
    print("INFO: Initialized TFLite interpreter pool.")

    scheduler = AsyncIOScheduler()
    scheduler.add_job(load_tranco_list, "interval", weeks=1, args=[redis_client], id="tranco_refresh")
    scheduler.add_job(load_umbrella_list, "interval", weeks=1, args=[redis_client], id="umbrella_refresh")
    
    try:
        # Load all whitelists concurrently at startup
        await asyncio.gather(
            load_india_seed_list(redis_client),  # fast, no network
            load_tranco_list(redis_client),
            load_umbrella_list(redis_client)
        )
    except Exception as e:
        print(f"WARNING: Initial whitelist load failed: {e}")
        
    scheduler.start()
    print("INFO: Whitelist refresh jobs scheduled (Tranco & Umbrella, interval: 1 week)")

    yield
    scheduler.shutdown(wait=False)
    await redis_client.aclose()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def index():
    return {"Malicious_status": "Yes"}


@app.post("/test_url")
async def get(request: Request, session: AsyncSession = Depends(get_session)):
    data = await request.json()
    test_url = data["url"]
    print(f"Analyzing URL: {test_url}")

    start_time = time.time()

    test_url = (
        test_url.replace("https://www.", "")
        .replace("http://www.", "")
        .replace("https://", "")
        .replace("http://", "")
    )
    domain = test_url.split("/")[0]

    if redis_client:
        try:
            cached_val = await redis_client.get(domain)
            if cached_val is not None:
                print(f"Cache hit for domain: {domain}")
                try:
                    payload = json.loads(cached_val)
                except ValueError:
                    payload = {"mal_status": int(cached_val)}
                payload["cached"] = True
                return payload
        except Exception as e:
            print(f"WARNING: Redis cache GET failed for {domain}: {e}")

    if await is_whitelisted(domain, redis_client):
        whitelist_payload = {
            "mal_status": 0,
            "inference_time_ms": 0.0,
            "cached": False,
            "whitelisted": True,
            "source": "whitelist",
            "features": {},
            "explanations": [],
        }
        record = ScanRecord(
            domain=domain,
            malicious_status=0,
            inference_time_ms=0.0,
        )
        session.add(record)
        await session.commit()
        return whitelist_payload

    features_array = await feature_extractions.extract_features(domain)

    feature_names = [
        "length",
        "n_ns",
        "n_vowels",
        "life_time",
        "n_vowel_chars",
        "n_constant_chars",
        "n_nums",
        "n_other_chars",
        "entropy",
        "n_mx",
        "ns_similarity",
        "n_countries",
        "n_labels",
    ]
    features_dict = dict(zip(feature_names, features_array))

    X_test = np.array(features_array, dtype=np.uint32)
    inp = np.expand_dims(X_test, axis=0)
    inp = inp.astype(np.float32)

    async with acquire_interpreter() as model_data:
        interpreter = model_data["interpreter"]
        input_details = model_data["input_details"]
        output_details = model_data["output_details"]

        def _run_inference():
            interpreter.set_tensor(input_details[0]["index"], inp)
            interpreter.invoke()
            return int(interpreter.get_tensor(output_details[0]["index"])[0][0])

        malicious_status = await asyncio.to_thread(_run_inference)

    end_time = time.time()
    inference_time_ms = (end_time - start_time) * 1000  # Convert to ms
    print(f"Inference Time: {inference_time_ms:.2f} ms")
    print(f"Malicious Status: {malicious_status}")

    explanations = translate(features_dict)

    response_payload = {
        "mal_status": malicious_status,
        "inference_time_ms": inference_time_ms,
        "features": features_dict,
        "explanations": explanations,
        "whitelisted": False,
        "source": "model",
    }

    if redis_client:
        try:
            await redis_client.set(domain, json.dumps(response_payload), ex=86400)
        except Exception as e:
            print(f"WARNING: Redis cache SET failed for {domain}: {e}")

    record = ScanRecord(
        domain=domain,
        malicious_status=malicious_status,
        inference_time_ms=inference_time_ms,
        features_json=json.dumps(features_dict),
        explanations_json=json.dumps(explanations),
    )
    session.add(record)
    await session.commit()

    return response_payload


@app.post("/whitelist", status_code=201)
async def add_whitelist(req: WhitelistRequest, session: AsyncSession = Depends(get_session)):
    ext = tldextract.extract(req.domain)
    registered_domain = ext.registered_domain
    if not registered_domain:
        raise HTTPException(status_code=422, detail="Invalid domain")
        
    result = await session.execute(select(UserWhitelist).where(UserWhitelist.domain == registered_domain))
    if result.scalars().first():
        raise HTTPException(status_code=409, detail="Domain already in whitelist")
        
    new_entry = UserWhitelist(domain=registered_domain, note=req.note)
    session.add(new_entry)
    await session.commit()
    
    if redis_client:
        await redis_client.sadd(REDIS_USER_WHITELIST_KEY, registered_domain)
        await redis_client.srem(REDIS_USER_BLACKLIST_KEY, registered_domain)
        await redis_client.delete(registered_domain)
        
    return {"status": "added", "domain": registered_domain}

@app.delete("/whitelist/{domain}")
async def remove_whitelist(domain: str, session: AsyncSession = Depends(get_session)):
    ext = tldextract.extract(domain)
    registered_domain = ext.registered_domain
    if not registered_domain:
        raise HTTPException(status_code=422, detail="Invalid domain")
        
    result = await session.execute(select(UserWhitelist).where(UserWhitelist.domain == registered_domain))
    entry = result.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found in whitelist")
        
    await session.delete(entry)
    await session.commit()
    
    if redis_client:
        await redis_client.srem(REDIS_USER_WHITELIST_KEY, registered_domain)
        await redis_client.delete(registered_domain)
        
    return {"status": "removed", "domain": registered_domain}

@app.post("/blacklist", status_code=201)
async def add_blacklist(req: BlacklistRequest, session: AsyncSession = Depends(get_session)):
    ext = tldextract.extract(req.domain)
    registered_domain = ext.registered_domain
    if not registered_domain:
        raise HTTPException(status_code=422, detail="Invalid domain")
        
    result = await session.execute(select(UserBlacklist).where(UserBlacklist.domain == registered_domain))
    if result.scalars().first():
        raise HTTPException(status_code=409, detail="Domain already in blacklist")
        
    new_entry = UserBlacklist(domain=registered_domain, note=req.note)
    session.add(new_entry)
    await session.commit()
    
    if redis_client:
        await redis_client.sadd(REDIS_USER_BLACKLIST_KEY, registered_domain)
        await redis_client.srem(REDIS_USER_WHITELIST_KEY, registered_domain)
        await redis_client.delete(registered_domain)
        
    return {"status": "added", "domain": registered_domain}

@app.delete("/blacklist/{domain}")
async def remove_blacklist(domain: str, session: AsyncSession = Depends(get_session)):
    ext = tldextract.extract(domain)
    registered_domain = ext.registered_domain
    if not registered_domain:
        raise HTTPException(status_code=422, detail="Invalid domain")
        
    result = await session.execute(select(UserBlacklist).where(UserBlacklist.domain == registered_domain))
    entry = result.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found in blacklist")
        
    await session.delete(entry)
    await session.commit()
    
    if redis_client:
        await redis_client.srem(REDIS_USER_BLACKLIST_KEY, registered_domain)
        await redis_client.delete(registered_domain)
        
    return {"status": "removed", "domain": registered_domain}

@app.get("/scans")
async def list_scans(page: int = 1, page_size: int = 20, session: AsyncSession = Depends(get_session)):
    if page_size > 100:
        page_size = 100
    
    offset = (page - 1) * page_size
    
    # Query for count
    count_stmt = select(ScanRecord)
    count_result = await session.execute(count_stmt)
    total = len(count_result.scalars().all()) # This is inefficient for large DBs, but using len on scalars is simple for now. 
    # Actually, better to use a count function if possible, but len on all scalars is okay for a limited size app.
    # Wait, in AsyncSession/SQLModel, a better way is select(func.count(ScanRecord.id))
    
    from sqlalchemy import func
    total_result = await session.execute(select(func.count(ScanRecord.id)))
    total = total_result.scalar()
    
    # Query for records
    stmt = select(ScanRecord).order_by(ScanRecord.timestamp.desc()).offset(offset).limit(page_size)
    result = await session.execute(stmt)
    records = result.scalars().all()
    
    scans = []
    for r in records:
        features = json.loads(r.features_json) if r.features_json else {}
        explanations = json.loads(r.explanations_json) if r.explanations_json else []
        scans.append({
            "id": r.id,
            "domain": r.domain,
            "malicious_status": r.malicious_status,
            "inference_time_ms": r.inference_time_ms,
            "timestamp": r.timestamp.isoformat(),
            "features": features,
            "explanations": explanations
        })
    
    total_pages = (total + page_size - 1) // page_size
    
    return {
        "scans": scans,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }


@app.get("/whitelist")
async def list_whitelist(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(UserWhitelist).order_by(UserWhitelist.created_at.desc()))
    entries = result.scalars().all()
    return {"entries": [{"domain": e.domain, "note": e.note, "created_at": e.created_at.isoformat()} for e in entries]}

@app.get("/blacklist")
async def list_blacklist(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(UserBlacklist).order_by(UserBlacklist.created_at.desc()))
    entries = result.scalars().all()
    return {"entries": [{"domain": e.domain, "note": e.note, "created_at": e.created_at.isoformat()} for e in entries]}


@app.get("/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    # total_scans
    total_result = await session.execute(select(func.count(ScanRecord.id)))
    total_scans = total_result.scalar() or 0
    
    # total_malicious
    malicious_result = await session.execute(select(func.count(ScanRecord.id)).where(ScanRecord.malicious_status == 1))
    total_malicious = malicious_result.scalar() or 0
    
    # total_benign
    benign_result = await session.execute(select(func.count(ScanRecord.id)).where(ScanRecord.malicious_status == 0))
    total_benign = benign_result.scalar() or 0
    
    # avg_inference_time_ms (inference_time_ms > 0)
    avg_result = await session.execute(select(func.avg(ScanRecord.inference_time_ms)).where(ScanRecord.inference_time_ms > 0))
    avg_inference_time_ms = avg_result.scalar() or 0.0
    
    # whitelist_hits (inference_time_ms == 0 AND (features_json IS NULL OR features_json == '{}'))
    whitelist_result = await session.execute(
        select(func.count(ScanRecord.id))
        .where(ScanRecord.inference_time_ms == 0)
        .where((ScanRecord.features_json.is_(None)) | (ScanRecord.features_json == '{}'))
    )
    whitelist_hits = whitelist_result.scalar() or 0
    
    # top_flagged (top 10 domains where malicious_status == 1)
    top_flagged_stmt = (
        select(ScanRecord.domain, func.count(ScanRecord.id).label("count"))
        .where(ScanRecord.malicious_status == 1)
        .group_by(ScanRecord.domain)
        .order_by(func.count(ScanRecord.id).desc())
        .limit(10)
    )
    top_flagged_result = await session.execute(top_flagged_stmt)
    top_flagged = [{"domain": row[0], "count": row[1]} for row in top_flagged_result.all()]
    
    # trend (last 14 days, grouped by date)
    import datetime
    fourteen_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=14)
    
    trend_stmt = (
        select(
            func.date(ScanRecord.timestamp).label("date"),
            func.sum(ScanRecord.malicious_status).label("malicious"),
            func.count(ScanRecord.id).label("total")
        )
        .where(ScanRecord.timestamp >= fourteen_days_ago)
        .group_by(func.date(ScanRecord.timestamp))
        .order_by(func.date(ScanRecord.timestamp).asc())
    )
    trend_result = await session.execute(trend_stmt)
    trend = []
    for row in trend_result.all():
        m = int(row[1]) if row[1] is not None else 0
        t = int(row[2]) if row[2] is not None else 0
        trend.append({
            "date": row[0],
            "malicious": m,
            "benign": t - m
        })
    
    return {
        "total_scans": total_scans,
        "total_malicious": total_malicious,
        "total_benign": total_benign,
        "avg_inference_time_ms": round(float(avg_inference_time_ms), 2),
        "whitelist_hits": whitelist_hits,
        "top_flagged": top_flagged,
        "trend": trend
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000)

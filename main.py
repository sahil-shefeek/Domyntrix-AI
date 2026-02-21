import time
import asyncio
import json
from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import redis.asyncio as redis
from sqlmodel.ext.asyncio.session import AsyncSession

import feature_extractions
from database import get_session
from models import ScanRecord
from ml_pool import init_pool, acquire_interpreter


redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    try:
        await redis_client.ping()
        print("INFO: Connected to Redis successfully.")
    except Exception as e:
        print(f"WARNING: Failed to connect to Redis during startup: {e}")

    await init_pool("lite_model_optimized_float16.tflite")
    print("INFO: Initialized TFLite interpreter pool.")
    yield
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

    response_payload = {
        "mal_status": malicious_status,
        "inference_time_ms": inference_time_ms,
        "features": features_dict,
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
    )
    session.add(record)
    await session.commit()

    return response_payload


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000)

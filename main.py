import time
import asyncio
from threading import Lock

import numpy as np
import tensorflow as tf
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import feature_extractions

interpreter = tf.lite.Interpreter(model_path="lite_model_optimized_float16.tflite")
interpreter.allocate_tensors()
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()
input_shape = input_details[0]["shape"]

interpreter_lock = Lock()


app = FastAPI()
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


def run_inference(inp):
    with interpreter_lock:
        interpreter.set_tensor(input_details[0]["index"], inp)
        interpreter.invoke()
        status = int(interpreter.get_tensor(output_details[0]["index"])[0][0])
    return status


@app.post("/test_url")
async def get(request: Request):
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

    features_array = await feature_extractions.extract_features(domain)

    X_test = np.array(features_array, dtype=np.uint32)
    inp = np.expand_dims(X_test, axis=0)
    inp = inp.astype(np.float32)

    malicious_status = await asyncio.to_thread(run_inference, inp)

    end_time = time.time()
    inference_time = (end_time - start_time) * 1000  # Convert to ms
    print(f"Inference Time: {inference_time:.2f} ms")
    print(f"Malicious Status: {malicious_status}")

    return {"mal_status": malicious_status}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000)

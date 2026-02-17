import time
import json
from threading import Lock

import numpy as np
import tensorflow as tf
from flask import Flask, request
from flask_cors import CORS

import feature_extractions

interpreter = tf.lite.Interpreter(model_path="lite_model_optimized_float16.tflite")
interpreter.allocate_tensors()
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()
input_details[0]["shape"]
input_shape = input_details[0]["shape"]

interpreter_lock = Lock()


# if __name__ == '__main__':
#     start('rgu.ac.uk')

app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    return json.dumps({"Malicious_status": "Yes"})


@app.route("/test_url", methods=["POST"])
def get():
    data = request.get_json()
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
    features_array = feature_extractions.extract_features(domain)
    # print(features_array)
    X_test = np.array(features_array, dtype=np.uint32)

    inp = np.expand_dims(X_test, axis=0)

    inp = inp.astype(np.float32)

    with interpreter_lock:
        interpreter.set_tensor(input_details[0]["index"], inp)
        interpreter.invoke()
        malicious_status = int(interpreter.get_tensor(output_details[0]["index"])[0][0])

    end_time = time.time()
    inference_time = (end_time - start_time) * 1000  # Convert to ms
    print(f"Inference Time: {inference_time:.2f} ms")
    print(f"Malicious Status: {malicious_status}")

    return json.dumps({"mal_status": malicious_status})


app.run()

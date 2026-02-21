import os
import asyncio
from contextlib import asynccontextmanager
import tensorflow as tf

POOL_SIZE = int(os.getenv("MODEL_POOL_SIZE", 4))

_pool = None


async def init_pool(model_path: str):
    global _pool
    _pool = asyncio.Queue(maxsize=POOL_SIZE)

    for _ in range(POOL_SIZE):
        interpreter = tf.lite.Interpreter(model_path=model_path)
        interpreter.allocate_tensors()

        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()

        await _pool.put(
            {
                "interpreter": interpreter,
                "input_details": input_details,
                "output_details": output_details,
            }
        )


@asynccontextmanager
async def acquire_interpreter():
    model_data = await _pool.get()
    try:
        yield model_data
    finally:
        _pool.put_nowait(model_data)

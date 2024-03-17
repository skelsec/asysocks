import asyncio
from websockets.sync.client import connect 

async def client():
    i = 0
    with connect("ws://localhost:8765") as websocket:
        while True:
            websocket.send(b"Hello world!" + b'A'*i*100)
            message = websocket.recv()
            print(f"Received: {message}")
            await asyncio.sleep(1)
            i += 1

asyncio.run(client())
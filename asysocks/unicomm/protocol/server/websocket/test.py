import asyncio
from asysocks.unicomm.protocol.server.websocket.server import serve

async def echo(websocket):
    await websocket.ping("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")
    async for message in websocket:
        print(f"Received: {message}")
        await websocket.send(message)
  

async def server():
    async with serve(echo, "localhost", 8765):  
        await asyncio.Future()  # run forever



asyncio.run(server())
# A counting TCP proxy: listens on 127.0.0.1:LISTEN, forwards to 127.0.0.1:TARGET,
# and on SIGTERM (or when the flag file FLAG goes away) writes
# {"c2s": bytes client->server, "s2c": bytes server->client, "connections": n} to OUT.
# usage: python3 -I proxy.py LISTEN TARGET OUT FLAG
import asyncio, json, os, signal, sys

listen, target, out, flag = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
tot = {"c2s": 0, "s2c": 0, "connections": 0}


async def pump(r, w, key):
    try:
        while True:
            d = await r.read(1 << 16)
            if not d:
                break
            tot[key] += len(d)
            w.write(d)
            await w.drain()
    except Exception:
        pass
    try:
        w.close()
    except Exception:
        pass


async def handle(cr, cw):
    tot["connections"] += 1
    try:
        sr, sw = await asyncio.open_connection("127.0.0.1", target)
    except Exception:
        cw.close()
        return
    await asyncio.gather(pump(cr, sw, "c2s"), pump(sr, cw, "s2c"))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", listen)
    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    async with server:
        while not stop.is_set() and os.path.exists(flag):
            try:
                await asyncio.wait_for(stop.wait(), 0.5)
            except asyncio.TimeoutError:
                pass
    with open(out, "w") as f:
        json.dump(tot, f)


asyncio.run(main())

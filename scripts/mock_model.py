#!/usr/bin/env python3
"""Mock inference-model services for eTrace-Diag end-to-end tests.

Serves:
  ws://127.0.0.1:9001/anomaly  -> AnomalyResult JSON (v1)
  ws://127.0.0.1:9002/causal    -> CausalResult JSON (opaque, always ok)

--trigger-once: the FIRST anomaly request returns is_anomaly=true; every later
request returns is_anomaly=false (so the collector enters DEEP exactly once and
then debounces back out).
"""
import argparse
import asyncio
import json

try:
    from websockets.asyncio.server import serve  # websockets >= 13
except ImportError:  # pragma: no cover - legacy websockets < 13
    from websockets import serve

ANOMALY_PORT = 9001
CAUSAL_PORT = 9002


async def anomaly_handler(ws, trigger_once, trigger_after):
    n = 0
    async for raw in ws:
        try:
            req = json.loads(raw)
            seq = req.get("seq", 0)
            ts_ns = req.get("ts_ns", 0)
            n += 1
            is_anomaly = trigger_once and n == trigger_after + 1
            reply = {
                "v": 1,
                "seq": seq,
                "ts_ns": ts_ns,
                "is_anomaly": is_anomaly,
                "type": "cpu",
                "confidence": 0.95,
                "indicators": [{"type": "cpu_high", "confidence": 0.95}],
            }
            await ws.send(json.dumps(reply))
        except Exception:
            import traceback

            traceback.print_exc()


async def causal_handler(ws):
    async for raw in ws:
        try:
            json.loads(raw)
            await ws.send(json.dumps({"v": 1, "ok": True}))
        except Exception:
            import traceback

            traceback.print_exc()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trigger-once", action="store_true",
                    help="return a single is_anomaly=true, then false")
    ap.add_argument("--trigger-after", type=int, default=0,
                    help="fire the single anomaly on request #(N+1)")
    ap.add_argument("--anomaly-port", type=int, default=ANOMALY_PORT)
    ap.add_argument("--causal-port", type=int, default=CAUSAL_PORT)
    args = ap.parse_args()

    async with serve(
        lambda ws: anomaly_handler(ws, args.trigger_once, args.trigger_after),
        "127.0.0.1", args.anomaly_port, max_size=32 * 1024 * 1024
    ), serve(causal_handler, "127.0.0.1", args.causal_port,
             max_size=32 * 1024 * 1024):
        print(f"mock anomaly model on ws://127.0.0.1:{args.anomaly_port}/anomaly "
              f"(trigger_once={args.trigger_once}, trigger_after={args.trigger_after})")
        print(f"mock causal model on ws://127.0.0.1:{args.causal_port}/causal")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
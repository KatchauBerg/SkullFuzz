import argparse
import asyncio
import json
import random
import string
import sys
from pathlib import Path

import aiohttp
from tqdm.asyncio import tqdm

UA = "Mozilla/5.0 (compatible; skullFuzz/1.0)"

SKULL = r'''
                       uuuuuuuuuuuuuuuuuuuuu.
                   .u$$$$$$$$$$$$$$$$$$$$$$$$$$W.
                 u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$Wu.
               $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$i
              $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
         `    $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
           .i$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$i
           $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$W
          .$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$W
         .$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$i
         #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$.
         W$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$u       #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$~
$#      `"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$i        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$        #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$         $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
#$.        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$#
 $$      $iW$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!
 $$i      $$$$$$$#"" `"""#$$$$$$$$$$$$$$$$$#""""""#$$$$$$$$$$$$$$$W
 #$$W    `$$$#"            "       !$$$$$`           `"#$$$$$$$$$$#
  $$$     ``                 ! !iuW$$$$$                 #$$$$$$$#
  #$$    $u                  $   $$$$$$$                  $$$$$$$~
   "#    #$$i.               #   $$$$$$$.                 `$$$$$$
          $$$$$i.                """#$$$$i.               .$$$$#
          $$$$$$$$!         .   `    $$$$$$$$$i           $$$$$
          `$$$$$  $iWW   .uW`        #$$$$$$$$$W.       .$$$$$$#
            "#$$$$$$$$$$$$#`          $$$$$$$$$$$iWiuuuW$$$$$$$$W
               !#""    ""             `$$$$$$$##$$$$$$$$$$$$$$$$
          i$$$$    .                   !$$$$$$ .$$$$$$$$$$$$$$$#
         $$$$$$$$$$`                    $$$$$$$$$Wi$$$$$$#"#$$`
         #$$$$$$$$$W.                   $$$$$$$$$$$#   ``
          `$$$$##$$$$!       i$u.  $. .i$$$$$$$$$#""
             "     `#W       $$$$$$$$$$$$$$$$$$$`      u$#
                            W$$$$$$$$$$$$$$$$$$      $$$$W
                            $$`!$$$##$$$$``$$$$      $$$$!
                           i$" $$$$  $$#"`  """     W$$$$
                                                   W$$$$!
                      uW$$  uu  uu.  $$$  $$$Wu#   $$$$$$
                     ~$$$$iu$$iu$$$uW$$! $$$$$$i .W$$$$$$
             ..  !   "#$$$$$$$$$$##$$$$$$$$$$$$$$$$$$$$#"
             $$W  $     "#$$$$$$$iW$$$$$$$$$$$$$$$$$$$$$W
             $#`   `       ""#$$$$$$$$$$$$$$$$$$$$$$$$$$$
                              !$$$$$$$$$$$$$$$$$$$$$#`
                              $$$$$$$$$$$$$$$$$$$$$$!
                            $$$$$$$$$$$$$$$$$$$$$$$`
                             $$$$$$$$$$$$$$$$$$$$"
'''

RETRY_STATUSES = {500, 502, 503, 504}
MARKER = "FUZZ"

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


class ThrottleController:
    """Adaptive throttle: ramps up sleep when 503s pile up in a sliding window."""

    def __init__(self, base_delay=0.0, window=10.0, threshold=3, max_extra=30.0):
        self.base_delay = base_delay
        self._window = window
        self._threshold = threshold
        self._max_extra = max_extra
        self._times: list[float] = []
        self._extra = 0.0
        self._lock = asyncio.Lock()

    async def record_503(self):
        now = asyncio.get_event_loop().time()
        async with self._lock:
            self._times.append(now)
            cutoff = now - self._window
            self._times = [t for t in self._times if t > cutoff]
            if len(self._times) >= self._threshold:
                self._extra = min(self._max_extra, (self._extra or 1.0) * 2.0)

    async def record_ok(self):
        async with self._lock:
            if self._extra > 0:
                self._extra = max(0.0, self._extra / 2.0)

    async def wait(self):
        delay = self.base_delay + self._extra
        if delay > 0:
            await asyncio.sleep(delay)


def load_words(path):
    raw = Path(path).read_text(errors="ignore").splitlines()
    return sorted({w.strip() for w in raw if w.strip() and not w.startswith("#")})


def parse_headers(header_list):
    """Parse ['Name: Value', ...] into dict."""
    headers = {}
    for h in (header_list or []):
        if ':' in h:
            k, v = h.split(':', 1)
            headers[k.strip()] = v.strip()
    return headers


def expand_targets(target, schemes, body_has_fuzz=False):
    """Return list of URL templates. FUZZ may be absent from URL if it's in --data."""
    if MARKER not in target and not body_has_fuzz:
        raise ValueError(
            f"Target URL or --data must contain '{MARKER}' marker.\n"
            f"  URL example:   https://site.com/{MARKER}\n"
            f"  Data example:  --data 'action={MARKER}'"
        )
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    return [f"{s}://{target}" for s in schemes]


async def fetch(session, url, timeout, method="GET", body=None, extra_headers=None):
    req_headers = dict(extra_headers or {})
    if body is not None and "content-type" not in {k.lower() for k in req_headers}:
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    kwargs = dict(timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False)
    if body is not None:
        kwargs["data"] = body

    async with session.request(method, url, headers=req_headers, **kwargs) as r:
        redirect = r.headers.get("Location") if 300 <= r.status < 400 else None
        resp_body = await r.read()
        return r.status, redirect, len(resp_body), resp_body


async def fetch_with_retry(session, url, timeout, retries, backoff, throttle,
                           method="GET", body=None, extra_headers=None):
    status = redirect = size = resp_body = None
    for attempt in range(retries + 1):
        try:
            status, redirect, size, resp_body = await fetch(
                session, url, timeout, method, body, extra_headers
            )
            if status in RETRY_STATUSES:
                await throttle.record_503()
                if attempt < retries:
                    jitter = random.uniform(0.5, 1.5)
                    await asyncio.sleep(backoff * (2 ** attempt) * jitter)
                    continue
            else:
                await throttle.record_ok()
            return status, redirect, size, resp_body
        except asyncio.TimeoutError:
            if attempt < retries:
                await asyncio.sleep(backoff * (2 ** attempt))
                continue
            raise
    return status, redirect, size, resp_body


async def wildcard_check(session, templates, timeout, method, data_template,
                         extra_headers, filter_body):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
    for tpl in templates:
        url  = tpl.replace(MARKER, rand) if MARKER in tpl else tpl
        body = data_template.replace(MARKER, rand) if data_template else None
        try:
            status, _, _, resp_body = await fetch(
                session, url, timeout, method, body, extra_headers
            )
            if 200 <= status < 400:
                text = resp_body.decode(errors="replace")
                if filter_body and filter_body.lower() in text.lower():
                    continue
                return url, status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
    return None


async def check(session, sem, word, templates, timeout, sink, verbose, match_codes,
                throttle, retries, backoff, filter_sizes, method, data_template,
                extra_headers, filter_body, match_body):
    async with sem:
        await throttle.wait()
        for tpl in templates:
            url  = tpl.replace(MARKER, word) if MARKER in tpl else tpl
            body = data_template.replace(MARKER, word) if data_template else None
            try:
                status, redirect, size, resp_body = await fetch_with_retry(
                    session, url, timeout, retries, backoff, throttle,
                    method, body, extra_headers
                )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                if verbose:
                    tqdm.write(f"{RED}[ERR]   [{word}] {url} — {type(e).__name__}: {e}{RESET}")
                continue

            text = resp_body.decode(errors="replace") if resp_body else ""

            if filter_body and filter_body.lower() in text.lower():
                if verbose:
                    tqdm.write(f"{YELLOW}[{status}]  {word} (filtered body){RESET}")
                continue
            if match_body and match_body.lower() not in text.lower():
                if verbose:
                    tqdm.write(f"{YELLOW}[{status}]  {word} (no body match){RESET}")
                continue

            hit = status in match_codes if match_codes else 200 <= status < 400
            if hit and filter_sizes and size in filter_sizes:
                if verbose:
                    tqdm.write(f"{YELLOW}[{status}]  {url} (filtered size={size}){RESET}")
                continue

            if hit:
                sink({"url": url, "word": word, "status": status,
                      "redirect": redirect, "size": size, "body": text[:400]})
            elif verbose:
                tqdm.write(f"{YELLOW}[{status}]  {word}{RESET}")


def expand_extensions(words, extensions):
    if not extensions:
        return words
    exts = []
    for e in extensions:
        e = e.strip()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        exts.append(e)
    out = []
    seen = set()
    for w in words:
        for cand in [w] + [w + e for e in exts]:
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


async def run(args):
    words = load_words(args.wordlist)
    if not words:
        print("Wordlist empty after dedupe.", file=sys.stderr)
        return 2

    if args.extensions:
        words = expand_extensions(words, args.extensions.split(","))

    data_template = getattr(args, "data", None) or None
    body_has_fuzz  = bool(data_template and MARKER in data_template)
    method         = (getattr(args, "method", None) or ("POST" if data_template else "GET")).upper()
    extra_headers  = parse_headers(getattr(args, "header", None))
    filter_body    = getattr(args, "filter_body", None)
    match_body     = getattr(args, "match_body", None)

    schemes = ["http", "https"] if args.scheme == "both" else [args.scheme]
    try:
        templates = expand_targets(args.target, schemes, body_has_fuzz)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    match_codes = None
    if args.match_codes:
        match_codes = {int(c) for c in args.match_codes.split(",")}

    filter_sizes = None
    if args.filter_size:
        filter_sizes = {int(s) for s in args.filter_size.split(",") if s.strip()}

    throttle = ThrottleController(base_delay=args.delay, threshold=args.throttle_threshold)
    sem  = asyncio.Semaphore(args.concurrency)
    conn = aiohttp.TCPConnector(limit=args.concurrency, ttl_dns_cache=300, ssl=False)

    out_fp  = open(args.output, "a") if args.output else None
    json_fp = open(args.json,   "a") if args.json   else None
    findings = []

    def sink(rec):
        findings.append(rec)
        word_part = f" word={rec['word']}" if rec.get("word") else ""
        size_part = f" [{rec['size']}b]"   if rec.get("size") is not None else ""
        body_preview = ""
        if rec.get("body") and data_template:
            body_preview = f"\n    {CYAN}{rec['body'][:160].strip()}{RESET}"
        line = (
            f"{GREEN}[FOUND]{word_part} {rec['url']} — {rec['status']}{size_part}"
            + (f" -> {rec['redirect']}" if rec.get("redirect") else "")
            + body_preview + RESET
        )
        tqdm.write(line)
        if out_fp:
            out_fp.write((rec.get("word") or rec["url"]) + "\n")
            out_fp.flush()
        if json_fp:
            json_fp.write(json.dumps({k: v for k, v in rec.items() if k != "body"}) + "\n")
            json_fp.flush()

    async with aiohttp.ClientSession(
        connector=conn, headers={"User-Agent": UA}
    ) as session:
        if not args.allow_wildcard:
            hit = await wildcard_check(
                session, templates, args.timeout, method,
                data_template, extra_headers, filter_body
            )
            if hit:
                print(
                    f"Wildcard match detected ({hit[0]} → {hit[1]}). "
                    "All results may be false positives. Use --allow-wildcard to skip.",
                    file=sys.stderr,
                )
                if data_template:
                    print(
                        "Tip: API fuzzing → add --allow-wildcard --filter-body '<error string>'",
                        file=sys.stderr,
                    )
                return 3

        tasks = [
            check(
                session, sem, w, templates, args.timeout, sink, args.verbose,
                match_codes, throttle, args.retries, args.backoff, filter_sizes,
                method, data_template, extra_headers, filter_body, match_body,
            )
            for w in words
        ]
        for coro in tqdm.as_completed(tasks, total=len(tasks), desc="fuzz"):
            await coro

    if out_fp:  out_fp.close()
    if json_fp: json_fp.close()

    if match_codes:
        summary = [r for r in findings if r["status"] in match_codes]
        hdr = f"matched ({','.join(str(c) for c in sorted(match_codes))})"
    else:
        summary = [r for r in findings if r["status"] == 200]
        hdr = "200 OK"

    print(f"\n=== Summary: {len(summary)} {hdr} ===")
    for r in sorted(summary, key=lambda x: (x["status"], x.get("word", x["url"]))):
        extra     = f" -> {r['redirect']}" if r.get("redirect") else ""
        word_part = f" [{r['word']}]"      if r.get("word")     else ""
        print(f"{GREEN}[{r['status']}]{RESET} {r['url']}{word_part}{extra}")
    return 0


# ── Interactive menu ──────────────────────────────────────────

def prompt(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{CYAN}{label}{suffix}{RESET}: ").strip()
    return val or (default if default is not None else "")


def interactive_menu():
    print(f"{RED}{SKULL}{RESET}")
    print(f"{BOLD}=== skullFuzz menu ==={RESET}")
    print("1) Path fuzz        (https://site.com/FUZZ)")
    print("2) Subdomain fuzz   (FUZZ.site.com)")
    print("3) Param fuzz GET   (https://site.com/?q=FUZZ)")
    print("4) POST body fuzz   (action=FUZZ  — API discovery)")
    print("5) Custom target")
    print("0) Quit")
    choice = prompt("Select", "1")
    if choice == "0":
        sys.exit(0)

    # ── target ──
    examples = {
        "1": "https://site.com/FUZZ",
        "2": "FUZZ.site.com",
        "3": "https://site.com/?q=FUZZ",
        "4": "https://site.com/api/index.php",
        "5": "",
    }
    while True:
        target = prompt(
            "Target URL" + ("" if choice == "4" else f" (must contain {MARKER})"),
            examples.get(choice, ""),
        )
        if not target:
            print(f"{RED}Target required.{RESET}")
            continue
        if choice not in ("4", "5") and MARKER not in target:
            print(f"{RED}Target must contain '{MARKER}' marker.{RESET}")
            continue
        break

    # ── POST-specific ──
    data_template = None
    headers_raw   = []
    method        = None
    filter_body   = None

    if choice == "4":
        raw = prompt(f"POST body template (use {MARKER})", f"action={MARKER}")
        data_template = raw or None
        print(f"{CYAN}Headers — one per line, empty line to finish:{RESET}")
        while True:
            h = input(f"  {CYAN}Header (e.g. Cookie: PHPSESSID=xxx){RESET}: ").strip()
            if not h:
                break
            headers_raw.append(h)
        filter_body = prompt("Filter body string (hits containing this are dropped)", "invalid") or None
        method = "POST"

    # ── wordlist ──
    while True:
        wordlist = prompt("Wordlist path", "wordlist.txt")
        if Path(wordlist).is_file():
            break
        print(f"{RED}File not found: {wordlist}{RESET}")

    concurrency       = int(prompt("Concurrency", "10"))
    timeout           = float(prompt("Timeout (s)", "5.0"))
    delay             = float(prompt("Delay per request (s)", "0.0"))
    retries           = int(prompt("Retries on 503/timeout", "3"))
    backoff           = float(prompt("Backoff base (s)", "1.0"))
    throttle_threshold = int(prompt("Auto-throttle threshold", "3"))
    scheme            = prompt("Scheme (http/https/both)", "both")
    match_codes       = prompt("Match codes (blank = 200-399)", "") or None
    extensions        = (prompt("Extensions (e.g. .php,.html, blank = none)", "") or None) if choice != "4" else None
    filter_size       = prompt("Filter sizes in bytes (blank = none)", "") or None
    output            = prompt("Output txt file (blank = none)", "") or None
    json_out          = prompt("Output JSONL file (blank = none)", "") or None
    allow_wildcard    = (choice == "4") or prompt("Allow wildcard? (y/N)", "n").lower().startswith("y")
    verbose           = prompt("Verbose? (y/N)", "n").lower().startswith("y")

    return argparse.Namespace(
        target=target, wordlist=wordlist,
        method=method, data=data_template,
        header=headers_raw or None,
        concurrency=concurrency, timeout=timeout, delay=delay,
        retries=retries, backoff=backoff, throttle_threshold=throttle_threshold,
        scheme=scheme, match_codes=match_codes, extensions=extensions,
        filter_size=filter_size, filter_body=filter_body, match_body=None,
        output=output, json=json_out,
        allow_wildcard=allow_wildcard, verbose=verbose,
    )


# ── CLI ──────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="skullFuzz — async HTTP fuzzer (GET & POST). FUZZ marker in URL or body.",
        epilog=(
            "Examples:\n"
            "  # Path fuzz (GET)\n"
            "  skullFuzz.py -u https://site.com/FUZZ -w wordlist.txt\n\n"
            "  # API action discovery (POST)\n"
            "  skullFuzz.py -u https://api.com/api.php -w actions.txt \\\n"
            "    -X POST -d 'action=FUZZ' \\\n"
            "    -H 'Cookie: PHPSESSID=abc123' \\\n"
            "    --allow-wildcard --filter-body 'invalid'\n\n"
            "  # POST param fuzz with auth header\n"
            "  skullFuzz.py -u https://site.com/search -w words.txt \\\n"
            "    -X POST -d 'q=FUZZ&page=1' \\\n"
            "    -H 'Authorization: Bearer token' --match-body 'result'\n\n"
            "  # Subdomain fuzz\n"
            "  skullFuzz.py -u FUZZ.site.com -w wordlist.txt\n\n"
            "  # Path fuzz with extensions + size filter\n"
            "  skullFuzz.py -u https://site.com/FUZZ -w wl.txt -x .php,.html -fs 0"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--url", dest="target", required=True,
                   help=f"Target URL or host. '{MARKER}' must appear in URL or --data.")
    p.add_argument("-w", "--wordlist", required=True,
                   help="Path to wordlist file.")
    p.add_argument("-X", "--method", default=None,
                   help="HTTP method (GET, POST, PUT…). Auto-detected: POST when -d given, else GET.")
    p.add_argument("-d", "--data", default=None,
                   help=f"POST body template containing '{MARKER}'. Example: 'action={MARKER}&id=1'")
    p.add_argument("-H", "--header", action="append", metavar="'Name: Value'",
                   help="Custom header (repeatable). Example: -H 'Cookie: x=y' -H 'X-Token: z'")
    p.add_argument("--filter-body", "--fb", dest="filter_body", default=None,
                   help="Drop hits whose response body contains this string (case-insensitive).")
    p.add_argument("--match-body", "--mb", dest="match_body", default=None,
                   help="Only flag hits whose response body contains this string.")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--delay", type=float, default=0.0,
                   help="Base delay (s) per worker slot (default 0.0).")
    p.add_argument("--retries", type=int, default=3,
                   help="Retry count on 503/timeout (default 3).")
    p.add_argument("--backoff", type=float, default=1.0,
                   help="Exponential backoff base in seconds (default 1.0).")
    p.add_argument("--throttle-threshold", type=int, default=3,
                   help="503s in 10s window before adaptive throttle kicks in (default 3).")
    p.add_argument("--scheme", choices=["http", "https", "both"], default="both",
                   help="Scheme when target has none (default both).")
    p.add_argument("--match-codes",
                   help="Comma-separated status codes to flag (e.g. 200,301,403). Default: 200-399.")
    p.add_argument("-x", "--extensions",
                   help="Comma-separated extensions to append (e.g. .php,.html,.bak).")
    p.add_argument("-fs", "--filter-size",
                   help="Comma-separated response sizes (bytes) to exclude.")
    p.add_argument("--output", help="Append-mode text file of found words/URLs.")
    p.add_argument("--json",   help="Append-mode JSONL file of findings.")
    p.add_argument("--allow-wildcard", action="store_true",
                   help="Skip wildcard pre-check (required for most POST API fuzzing).")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show every probe: green=found, yellow=filtered, red=error.")
    return p.parse_args()


def main():
    if len(sys.argv) == 1:
        args = interactive_menu()
    else:
        args = parse_args()
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

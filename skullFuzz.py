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

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def load_words(path):
    raw = Path(path).read_text(errors="ignore").splitlines()
    return sorted({w.strip() for w in raw if w.strip() and not w.startswith("#")})


def expand_targets(target, schemes):
    """Return list of URL templates each containing MARKER."""
    if MARKER not in target:
        raise ValueError(f"Target must contain '{MARKER}' marker. Example: https://site.com/{MARKER}")
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    return [f"{s}://{target}" for s in schemes]


async def fetch(session, url, timeout):
    async with session.get(
        url,
        timeout=aiohttp.ClientTimeout(total=timeout),
        allow_redirects=False,
    ) as r:
        redirect = r.headers.get("Location") if 300 <= r.status < 400 else None
        return r.status, redirect


async def fetch_with_retry(session, url, timeout):
    try:
        status, redirect = await fetch(session, url, timeout)
        if status in RETRY_STATUSES:
            await asyncio.sleep(0.5)
            status, redirect = await fetch(session, url, timeout)
        return status, redirect
    except asyncio.TimeoutError:
        await asyncio.sleep(0.5)
        return await fetch(session, url, timeout)


async def check(session, sem, word, templates, timeout, sink, verbose, match_codes):
    async with sem:
        for tpl in templates:
            url = tpl.replace(MARKER, word)
            try:
                status, redirect = await fetch_with_retry(session, url, timeout)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                if verbose:
                    tqdm.write(f"{RED}[ERR]   {url} - {type(e).__name__}: {e}{RESET}")
                continue
            hit = status in match_codes if match_codes else 200 <= status < 400
            if hit:
                sink({"url": url, "status": status, "redirect": redirect})
            elif verbose:
                tqdm.write(f"{YELLOW}[{status}]  {url}{RESET}")


async def wildcard_check(session, templates, timeout):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
    for tpl in templates:
        url = tpl.replace(MARKER, rand)
        try:
            status, _ = await fetch(session, url, timeout)
            if 200 <= status < 400:
                return url, status
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
    return None


async def run(args):
    words = load_words(args.wordlist)
    if not words:
        print("Wordlist empty after dedupe.", file=sys.stderr)
        return 2

    schemes = ["http", "https"] if args.scheme == "both" else [args.scheme]
    try:
        templates = expand_targets(args.target, schemes)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    match_codes = None
    if args.match_codes:
        match_codes = {int(c) for c in args.match_codes.split(",")}

    sem = asyncio.Semaphore(args.concurrency)
    conn = aiohttp.TCPConnector(limit=args.concurrency, ttl_dns_cache=300, ssl=False)
    headers = {"User-Agent": UA}

    out_fp = open(args.output, "a") if args.output else None
    json_fp = open(args.json, "a") if args.json else None
    findings = []

    def sink(rec):
        findings.append(rec)
        line = f"{GREEN}[FOUND] {rec['url']} - {rec['status']}" + (
            f" -> {rec['redirect']}" if rec["redirect"] else ""
        ) + RESET
        tqdm.write(line)
        if out_fp:
            out_fp.write(rec["url"] + "\n")
            out_fp.flush()
        if json_fp:
            json_fp.write(json.dumps(rec) + "\n")
            json_fp.flush()

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        if not args.allow_wildcard:
            hit = await wildcard_check(session, templates, args.timeout)
            if hit:
                print(
                    f"Wildcard match detected ({hit[0]} -> {hit[1]}). "
                    "All results may be false positives. Use --allow-wildcard to override.",
                    file=sys.stderr,
                )
                return 3

        tasks = [
            check(session, sem, w, templates, args.timeout, sink, args.verbose, match_codes)
            for w in words
        ]
        for coro in tqdm.as_completed(tasks, total=len(tasks), desc="fuzz"):
            await coro

    if out_fp:
        out_fp.close()
    if json_fp:
        json_fp.close()

    if match_codes:
        summary = [r for r in findings if r["status"] in match_codes]
        header = f"matched ({','.join(str(c) for c in sorted(match_codes))})"
    else:
        summary = [r for r in findings if r["status"] == 200]
        header = "200 OK"
    print(f"\n=== Summary: {len(summary)} {header} ===")
    for r in sorted(summary, key=lambda x: (x["status"], x["url"])):
        extra = f" -> {r['redirect']}" if r["redirect"] else ""
        print(f"{GREEN}[{r['status']}]{RESET} {r['url']}{extra}")
    return 0


CYAN = "\033[36m"
BOLD = "\033[1m"


def prompt(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{CYAN}{label}{suffix}{RESET}: ").strip()
    return val or (default if default is not None else "")


def interactive_menu():
    print(f"{RED}{SKULL}{RESET}")
    print(f"{BOLD}=== skullFuzz menu ==={RESET}")
    print("1) Path fuzz       (https://site.com/FUZZ)")
    print("2) Subdomain fuzz  (FUZZ.site.com)")
    print("3) Param fuzz      (https://site.com/?q=FUZZ)")
    print("4) Custom target")
    print("0) Quit")
    choice = prompt("Select", "1")
    if choice == "0":
        sys.exit(0)

    examples = {
        "1": "https://site.com/FUZZ",
        "2": "FUZZ.site.com",
        "3": "https://site.com/?q=FUZZ",
        "4": "",
    }
    while True:
        target = prompt("Target (must contain FUZZ)", examples.get(choice, ""))
        if not target:
            print(f"{RED}Target required.{RESET}")
            continue
        if MARKER not in target:
            print(f"{RED}Target must contain '{MARKER}' marker.{RESET}")
            continue
        break

    while True:
        wordlist = prompt("Wordlist path", "wordlist.txt")
        if Path(wordlist).is_file():
            break
        print(f"{RED}File not found: {wordlist}{RESET}")
    concurrency = int(prompt("Concurrency", "50"))
    timeout = float(prompt("Timeout (s)", "5.0"))
    scheme = prompt("Scheme (http/https/both)", "both")
    match_codes = prompt("Match codes (blank = 200-399)", "") or None
    output = prompt("Output txt file (blank = none)", "") or None
    json_out = prompt("Output JSONL file (blank = none)", "") or None
    allow_wildcard = prompt("Allow wildcard? (y/N)", "n").lower().startswith("y")
    verbose = prompt("Verbose? (y/N)", "n").lower().startswith("y")

    return argparse.Namespace(
        target=target,
        wordlist=wordlist,
        concurrency=concurrency,
        timeout=timeout,
        scheme=scheme,
        match_codes=match_codes,
        output=output,
        json=json_out,
        allow_wildcard=allow_wildcard,
        verbose=verbose,
    )


def parse_args():
    p = argparse.ArgumentParser(
        description="skullFuzz - async fuzzer with FUZZ marker.",
        epilog="Examples:\n"
               "  skullFuzz.py https://site.com/FUZZ wordlist.txt        (path fuzz)\n"
               "  skullFuzz.py FUZZ.site.com wordlist.txt                (subdomain fuzz)\n"
               "  skullFuzz.py 'https://site.com/?q=FUZZ' wordlist.txt   (param fuzz)\n"
               "  skullFuzz.py https://site.com/api/FUZZ/users wl.txt    (segment fuzz)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help=f"URL or host containing '{MARKER}' marker.")
    p.add_argument("wordlist")
    p.add_argument("--concurrency", type=int, default=50)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--scheme", choices=["http", "https", "both"], default="both",
                   help="Used only when target has no scheme.")
    p.add_argument("--match-codes", help="Comma-separated status codes to flag (e.g. 200,301,403). Default: 200-399.")
    p.add_argument("--output", help="Append-mode text file of found URLs.")
    p.add_argument("--json", help="Append-mode JSONL file of findings.")
    p.add_argument("--allow-wildcard", action="store_true",
                   help="Skip wildcard pre-check.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show every probe: green=found, yellow=non-match, red=error.")
    return p.parse_args()


def main():
    if len(sys.argv) == 1:
        args = interactive_menu()
    else:
        args = parse_args()
        if MARKER not in args.target and MARKER in args.wordlist and Path(args.target).is_file():
            print(f"{YELLOW}Swapping target/wordlist (looks reversed).{RESET}", file=sys.stderr)
            args.target, args.wordlist = args.wordlist, args.target
    try:
        sys.exit(asyncio.run(run(args)))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

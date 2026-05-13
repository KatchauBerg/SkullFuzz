# skullFuzz

Async HTTP fuzzer with `FUZZ` marker. Path, subdomain, param, or segment fuzzing. Includes adaptive anti-503 throttle.

## Install

```bash
git clone <repo-url>
cd fastFuzz
python3 -m venv .venv
source .venv/bin/activate
pip install aiohttp tqdm
```

## Usage

Interactive menu (no args):

```bash
python skullFuzz.py
```

CLI:

```bash
python skullFuzz.py <target> <wordlist> [options]
```

Target must contain `FUZZ` marker.

### Examples

```bash
# Path fuzz
python skullFuzz.py https://site.com/FUZZ wordlist.txt

# Subdomain fuzz (no scheme = tries http + https)
python skullFuzz.py FUZZ.site.com wordlist.txt

# Param fuzz
python skullFuzz.py 'https://site.com/?q=FUZZ' wordlist.txt

# Segment fuzz
python skullFuzz.py https://site.com/api/FUZZ/users wordlist.txt

# CTF target that rate-limits (aggressive anti-503 settings)
python skullFuzz.py https://ctf.site/FUZZ wordlist.txt \
  --concurrency 5 --delay 0.3 --retries 3 --backoff 1.0 -v
```

## Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--concurrency N` | 10 | Parallel workers |
| `--timeout S` | 5.0 | Per-request timeout (seconds) |
| `--delay S` | 0.0 | Fixed pause (s) before each request slot |
| `--retries N` | 3 | Retry count on 503/timeout |
| `--backoff S` | 1.0 | Exponential backoff base (s): `backoff * 2^attempt * jitter` |
| `--throttle-threshold N` | 3 | 503s in 10s window before auto-throttle activates |
| `--scheme http\|https\|both` | both | Scheme when target has none |
| `--match-codes 200,301,403` | 200-399 | Status codes to flag as hits |
| `--output FILE` | — | Append found URLs (txt) |
| `--json FILE` | — | Append findings (JSONL) |
| `--allow-wildcard` | off | Skip wildcard pre-check |
| `-v`, `--verbose` | off | Show every probe |

## Anti-503 / Rate-limit Handling

The fuzzer has two layers of 503 defense:

### 1. Exponential backoff (per request)
On each 503 or timeout, retries with increasing wait:
```
attempt 0 fails → wait backoff * 1 * jitter
attempt 1 fails → wait backoff * 2 * jitter
attempt 2 fails → wait backoff * 4 * jitter
```
Jitter is `uniform(0.5, 1.5)` to avoid thundering-herd. Retries up to `--retries` times.

### 2. Adaptive throttle (global)
Tracks 503s across all workers in a 10-second sliding window.  
When 503 count hits `--throttle-threshold`:
- adds a global sleep that **doubles** each time more 503s arrive (1s → 2s → 4s → … max 30s)
- **halves** back down as successful responses come in

Combined with `--delay`, every worker pauses `delay + adaptive_extra` before acquiring a request slot.

### Tuning for fragile targets

| Target behavior | Suggested flags |
|----------------|-----------------|
| Allows ~50 req/s | defaults (concurrency 10, no delay) |
| Rate-limits after burst | `--delay 0.2 --concurrency 5` |
| Hard 503 wall, strict WAF | `--delay 0.5 --concurrency 3 --backoff 2.0` |
| Very strict / CTF rate-limit | `--delay 1.0 --concurrency 1 --retries 5 --backoff 2.0` |

## Output

- `[FOUND]` green = status matched
- `[code]` yellow = non-match (verbose only)
- `[ERR]` red = request error (verbose only)

JSONL record format:
```json
{"url": "https://site.com/admin", "status": 200, "redirect": null}
{"url": "https://site.com/login", "status": 301, "redirect": "/login/"}
```

## Wildcard Detection

Before fuzzing, sends a random 32-char string. If server returns 2xx/3xx, aborts — every path would match, making results useless. Override with `--allow-wildcard`.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed normally |
| `2` | Bad args or empty wordlist |
| `3` | Wildcard detected |
| `130` | Interrupted (Ctrl-C) |

## Legal

Authorized testing only.

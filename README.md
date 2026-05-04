# skullFuzz

Async HTTP fuzzer with `FUZZ` marker. Path, subdomain, param, or segment fuzzing.

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
```

## Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--concurrency N` | 50 | Parallel requests |
| `--timeout S` | 5.0 | Per-request timeout (seconds) |
| `--scheme http\|https\|both` | both | Scheme when target has none |
| `--match-codes 200,301,403` | 200-399 | Status codes to flag |
| `--output FILE` | - | Append found URLs (txt) |
| `--json FILE` | - | Append findings (JSONL) |
| `--allow-wildcard` | off | Skip wildcard pre-check |
| `-v`, `--verbose` | off | Show every probe |

## Output

- `[FOUND]` green = match
- `[code]` yellow = non-match (verbose only)
- `[ERR]` red = request error (verbose only)

JSONL record: `{"url": ..., "status": ..., "redirect": ...}`

## Wildcard detection

Before fuzz, sends random 32-char string. If response is 2xx/3xx, aborts (would yield false positives). Override with `--allow-wildcard`.

## Exit codes

- `0` ok
- `2` bad args / empty wordlist
- `3` wildcard detected
- `130` interrupted

## Legal

Authorized testing only.

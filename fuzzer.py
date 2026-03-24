#!/usr/bin/env python3
# RUZZ - Web CTF Fuzzing Command Generator
# by zoro_rj
#
# No external Python packages required.
# All dependencies are Python standard library:
#   - sys, os, re, shutil
#
# Python >= 3.6 required (f-strings)
#
# ── External Tools (install separately) ──────────────────
# ffuf          → https://github.com/ffuf/ffuf
# feroxbuster   → https://github.com/epi052/feroxbuster
# wfuzz         → pip install wfuzz
# gobuster      → https://github.com/OJ/gobuster
# dirsearch     → pip install dirsearch
#
# ── Wordlists ─────────────────────────────────────────────
# SecLists      → https://github.com/danielmiessler/SecLists
#   Install: sudo apt install seclists
#   Or:      git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

import sys
import os
import re
import shutil

# ─── ANSI Colors ──────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

def banner():
    print(f"""{C.GREEN}{C.BOLD}
           ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
           ┃                                                      ┃
           ┃          {C.CYAN}██████╗ ██╗   ██╗███████╗███████╗{C.GREEN}           ┃
           ┃          {C.CYAN}██╔══██╗██║   ██║╚══███╔╝╚══███╔╝{C.GREEN}           ┃
           ┃          {C.CYAN}██████╔╝██║   ██║  ███╔╝   ███╔╝ {C.GREEN}           ┃
           ┃          {C.CYAN}██╔══██╗██║   ██║ ███╔╝   ███╔╝  {C.GREEN}           ┃
           ┃          {C.CYAN}██║  ██║╚██████╔╝███████╗███████╗{C.GREEN}           ┃
           ┃          {C.CYAN}╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝{C.GREEN}           ┃
           ┃                                                      ┃
           ┃         {C.YELLOW}▸ web ctf fuzzing command generator{C.GREEN}          ┃
           ┃                                                      ┃
           ┃   {C.RED}◉ {C.YELLOW}◉ {C.GREEN}◉{C.GREEN}                              {C.DIM}▕{C.GREEN}▓▓▓▓▓▓▓{C.DIM}▏{C.GREEN} {C.DIM}57%{C.GREEN}   ┃
           ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
           {C.DIM}                    ┃             ┃
                               ┗━━━━━━━━━━━━━┛{C.GREEN}
           ┌────────────────────────────────────────────────────┐
           │  {C.RED}PWR{C.GREEN}  {C.DIM}[▪] [▪] [▪] [▪] [▪] [▪] [▪] [▪] [▪] [▪]{C.GREEN}  │
           └────────────────────────────────────────────────────┘{C.RESET}

        {C.RED}[!]{C.RESET}  {C.WHITE}ffuf  {C.DIM}|  {C.WHITE}feroxbuster  {C.DIM}|  {C.WHITE}wfuzz  {C.DIM}|  {C.WHITE}gobuster  {C.DIM}|  {C.WHITE}dirsearch{C.RESET}
        {C.DIM}  ──────────────────────────────────────────────────{C.RESET}
        {C.CYAN}                       by {C.BOLD}zoro_rj{C.RESET}
""")

# ─── Resource Impact Profiles ─────────────────────────────────────────────────

PROFILES = {
    "1": {
        "name":        "low",
        "label":       f"{C.GREEN}Low Impact{C.RESET}  — browser-friendly (~30 req/s, 5 threads)",
        "threads":     "5",
        "rate":        "30",
        "delay_ms":    "30",
        "wfuzz_delay": "0.03",
        "nice_prefix": "nice -n 19 ",
    },
    "2": {
        "name":        "medium",
        "label":       f"{C.YELLOW}Medium{C.RESET}      — balanced (~80 req/s, 20 threads)",
        "threads":     "20",
        "rate":        "80",
        "delay_ms":    "10",
        "wfuzz_delay": "0.01",
        "nice_prefix": "nice -n 10 ",
    },
    "3": {
        "name":        "high",
        "label":       f"{C.RED}High / Full Speed{C.RESET} — no limits (will saturate network & CPU)",
        "threads":     "40",
        "rate":        None,
        "delay_ms":    None,
        "wfuzz_delay": None,
        "nice_prefix": "",
    },
}

# ─── Paths & Wordlists ────────────────────────────────────────────────────────

WC  = "/usr/share/seclists/Discovery/Web-Content"
DNS = "/usr/share/seclists/Discovery/DNS"

WORDLISTS = {
    "directory":               f"{WC}/common.txt",
    "directory_medium":        f"{WC}/raft-medium-directories.txt",
    "directory_large":         f"{WC}/raft-large-directories.txt",
    "directory_small":         f"{WC}/raft-small-directories.txt",
    "directory_dirbuster_med": f"{WC}/DirBuster-2007_directory-list-2.3-medium.txt",
    "directory_dirbuster_big": f"{WC}/DirBuster-2007_directory-list-2.3-big.txt",
    "directory_combined":      f"{WC}/combined_directories.txt",
    "files_medium":            f"{WC}/raft-medium-files.txt",
    "files_large":             f"{WC}/raft-large-files.txt",
    "files_small":             f"{WC}/raft-small-files.txt",
    "words_medium":            f"{WC}/raft-medium-words.txt",
    "words_large":             f"{WC}/raft-large-words.txt",
    "extensions":              f"{WC}/web-extensions.txt",
    "extensions_big":          f"{WC}/web-extensions-big.txt",
    "parameter":               f"{WC}/burp-parameter-names.txt",
    "url_params":              f"{WC}/url-params_from-top-55-most-popular-apps.txt",
    "subdomain":               f"{DNS}/subdomains-top1million-5000.txt",
    "subdomain_large":         f"{DNS}/subdomains-top1million-20000.txt",
    "vhost":                   f"{DNS}/subdomains-top1million-5000.txt",
    "api":                     f"{WC}/common-api-endpoints-mazen160.txt",
    "api_graphql":             f"{WC}/graphql.txt",
    "quickhits":               f"{WC}/quickhits.txt",
    "big":                     f"{WC}/big.txt",
}

# default wordlist per fuzz type key — used in quick mode
TYPE_DEFAULT_WORDLIST = {
    "1": WORDLISTS["directory"],
    "2": WORDLISTS["parameter"],
    "3": WORDLISTS["subdomain"],
    "4": WORDLISTS["vhost"],
    "5": WORDLISTS["api"],
    "6": WORDLISTS["extensions"],
}

FUZZ_TYPES = {
    "1": "Directory/Subdirectory Fuzzing",
    "2": "Parameter Fuzzing",
    "3": "Subdomain Fuzzing",
    "4": "VHOST Fuzzing",
    "5": "API Endpoint Fuzzing",
    "6": "File Extension Fuzzing",
}

# short name aliases for quick mode typing
FUZZ_TYPE_ALIASES = {
    "dir": "1", "directory": "1",
    "param": "2", "parameter": "2",
    "sub": "3", "subdomain": "3",
    "vhost": "4",
    "api": "5",
    "ext": "6", "extension": "6",
}

TOOLS = {
    "1": "ffuf",
    "2": "feroxbuster",
    "3": "wfuzz",
    "4": "gobuster",
    "5": "dirsearch",
}

TOOL_ALIASES = {
    "ffuf": "1",
    "feroxbuster": "2",
    "wfuzz": "3",
    "gobuster": "4",
    "dirsearch": "5",
}

PROFILE_ALIASES = {
    "low": "1",
    "medium": "2", "med": "2",
    "high": "3",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def prompt(msg, default=None, color=C.CYAN):
    suffix = f"{C.DIM} [{default}]{C.RESET}" if default else ""
    val = input(f"{color}{C.BOLD}  ➜ {C.RESET}{color}{msg}{suffix}{C.RESET}: ").strip()
    return val if val else default

def choose(msg, options: dict, color=C.YELLOW):
    print(f"\n{color}{C.BOLD}  {msg}{C.RESET}")
    for k, v in options.items():
        icon = "⚡" if k == "1" else "▸"
        print(f"  {C.DIM}{k}{C.RESET}) {icon} {v}")
    while True:
        choice = prompt("Enter choice", color=color)
        if choice in options:
            return choice
        print(f"  {C.RED}✗ Invalid choice. Try again.{C.RESET}")

def section(title):
    print(f"\n{C.BLUE}{'─'*55}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.BLUE}{'─'*55}{C.RESET}")

def warn(msg):    print(f"  {C.YELLOW}⚠  {msg}{C.RESET}")
def info(msg):    print(f"  {C.DIM}ℹ  {msg}{C.RESET}")
def success(msg): print(f"  {C.GREEN}✔  {msg}{C.RESET}")

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def validate_url(url):
    return bool(re.compile(r'^https?://.+', re.IGNORECASE).match(url))

def normalize_target(target):
    """Ensure target has a scheme and no trailing slash."""
    if not target:
        return target
    if not validate_url(target):
        target = "http://" + target
    return target.rstrip("/")

# ─── Mode Selector ────────────────────────────────────────────────────────────

def select_mode():
    print(f"\n{C.MAGENTA}{'─'*55}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}  How do you want to build your command?{C.RESET}")
    print(f"{C.MAGENTA}{'─'*55}{C.RESET}\n")
    print(f"  {C.DIM}1{C.RESET}) {C.YELLOW}⚡ Quick{C.RESET}   — single screen, rapid-fire prompts, instant command")
    print(f"  {C.DIM}2{C.RESET}) {C.CYAN}▸ Manual{C.RESET}  — step-by-step guided mode (better for beginners)\n")
    while True:
        choice = prompt("Enter choice", "1", color=C.MAGENTA)
        if choice in ("1", "2"):
            return choice
        print(f"  {C.RED}✗ Enter 1 or 2.{C.RESET}")

# ─── Profile Selector (manual mode) ──────────────────────────────────────────

def select_profile():
    section("Step 0: Resource Impact Profile")
    print(f"""
  {C.WHITE}Fuzzing sends hundreds of requests per second by default.{C.RESET}
  {C.DIM}This saturates your network and makes your browser slow.{C.RESET}
  {C.DIM}Pick a profile to control the impact on your machine.{C.RESET}
""")
    key = choose("How hard should we fuzz?", {k: v["label"] for k, v in PROFILES.items()}, color=C.MAGENTA)
    profile = PROFILES[key]

    if profile["name"] == "low":
        print(f"""
  {C.GREEN}✔  Low-Impact mode selected.{C.RESET}
  {C.DIM}  • Threads    : {profile['threads']}
    • Rate limit : {profile['rate']} req/s
    • nice level : 19 (lowest CPU priority){C.RESET}
  {C.GREEN}  Your browser and other apps will stay responsive.{C.RESET}""")
    elif profile["name"] == "medium":
        print(f"""
  {C.YELLOW}✔  Medium mode selected.{C.RESET}
  {C.DIM}  • Threads    : {profile['threads']}
    • Rate limit : {profile['rate']} req/s
    • nice level : 10{C.RESET}
  {C.YELLOW}  Some slowdown expected on slower machines.{C.RESET}""")
    else:
        print(f"""
  {C.RED}✔  High Speed mode selected.{C.RESET}
  {C.DIM}  • Threads    : {profile['threads']} (no cap)
    • Rate limit : none
    • nice level : none{C.RESET}
  {C.RED}  ⚠  Expect browser slowdowns and network saturation.{C.RESET}""")
    return profile

# ─── Wordlist Prompts (manual mode) ───────────────────────────────────────────

def ask_wordlist_directory():
    options = {
        "1": ("common",             WORDLISTS["directory"]),
        "2": ("raft-medium-dirs",   WORDLISTS["directory_medium"]),
        "3": ("raft-large-dirs",    WORDLISTS["directory_large"]),
        "4": ("raft-small-dirs",    WORDLISTS["directory_small"]),
        "5": ("dirbuster-medium",   WORDLISTS["directory_dirbuster_med"]),
        "6": ("dirbuster-big",      WORDLISTS["directory_dirbuster_big"]),
        "7": ("combined-dirs",      WORDLISTS["directory_combined"]),
        "8": ("big",                WORDLISTS["big"]),
        "9": ("quickhits",          WORDLISTS["quickhits"]),
        "c": ("custom path",        None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Directory Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        print(f"  {C.DIM}{k}{C.RESET}) {label:<25} {C.CYAN}{path or 'enter manually'}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            return prompt("Enter custom wordlist path", WORDLISTS["directory"], C.MAGENTA) if path is None else path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_parameter():
    options = {
        "1": ("burp-parameter-names",  WORDLISTS["parameter"]),
        "2": ("url-params-top55-apps", WORDLISTS["url_params"]),
        "c": ("custom path",           None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Parameter Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{path or 'enter manually'}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            return prompt("Enter custom wordlist path", WORDLISTS["parameter"], C.MAGENTA) if path is None else path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_subdomain():
    options = {
        "1": ("subdomains-top1million-5000",  WORDLISTS["subdomain"]),
        "2": ("subdomains-top1million-20000", WORDLISTS["subdomain_large"]),
        "c": ("custom path",                  None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Subdomain Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{path or 'enter manually'}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            return prompt("Enter custom wordlist path", WORDLISTS["subdomain"], C.MAGENTA) if path is None else path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_api():
    options = {
        "1": ("common-api-endpoints-mazen160", WORDLISTS["api"]),
        "2": ("graphql",                        WORDLISTS["api_graphql"]),
        "3": ("raft-medium-words",              WORDLISTS["words_medium"]),
        "c": ("custom path",                    None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}API Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{path or 'enter manually'}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            return prompt("Enter custom wordlist path", WORDLISTS["api"], C.MAGENTA) if path is None else path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_extension():
    options = {
        "1": ("web-extensions",     WORDLISTS["extensions"]),
        "2": ("web-extensions-big", WORDLISTS["extensions_big"]),
        "c": ("custom path",        None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Extension Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        print(f"  {C.DIM}{k}{C.RESET}) {label:<25} {C.CYAN}{path or 'enter manually'}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            return prompt("Enter custom wordlist path", WORDLISTS["extensions"], C.MAGENTA) if path is None else path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

WORDLIST_ASKERS = {
    "1": ask_wordlist_directory,
    "2": ask_wordlist_parameter,
    "3": ask_wordlist_subdomain,
    "4": ask_wordlist_subdomain,
    "5": ask_wordlist_api,
    "6": ask_wordlist_extension,
}

# ─── Shared Option Prompts ────────────────────────────────────────────────────

def ask_extensions():
    raw = prompt("Extensions to fuzz (e.g. php,txt,html — ENTER to skip)", "", C.CYAN)
    return ",".join(e.strip().lstrip(".") for e in raw.split(",")) if raw else None

def ask_threads(profile):
    return prompt("Threads", profile["threads"], C.CYAN)

def ask_rate_limit(profile):
    rec = profile["rate"]
    if rec:
        info(f"Profile recommends {rec} req/s.")
        val = prompt("Rate limit req/s (0 to disable)", rec, C.CYAN)
        return val if val and val != "0" else None
    val = prompt("Rate limit req/s (ENTER = no limit)", "", C.CYAN)
    return val if val else None

def ask_extra_flags():
    raw = prompt("Extra flags (ENTER to skip)", "", C.CYAN)
    return raw if raw else ""

def ask_headers():
    raw = prompt("Custom header (e.g. Cookie: x=y — ENTER to skip)", "", C.CYAN)
    return raw if raw else None

def ask_filter_options():
    filters = {}
    fc = prompt("Hide status codes (e.g. 404,403 — ENTER to skip)", "", C.CYAN)
    if fc: filters["fc"] = fc
    fs = prompt("Filter response size bytes (ENTER to skip)", "", C.CYAN)
    if fs: filters["fs"] = fs
    fw = prompt("Filter word count (ENTER to skip)", "", C.CYAN)
    if fw: filters["fw"] = fw
    return filters

def ask_output_file():
    if prompt("Save output to file? (y/N)", "n", C.CYAN).lower() == "y":
        return prompt("Output file path", "fuzz_output.txt", C.CYAN)
    return None

# ─── Command Builders ─────────────────────────────────────────────────────────

def build_ffuf(target, fuzz_type, wordlist, **kw):
    p   = kw.get("profile", PROFILES["3"])
    cmd = ["ffuf"]

    if fuzz_type == "1":
        cmd += ["-u", kw.get("url", f"{target}/FUZZ"), "-w", wordlist]
        if kw.get("extensions"):
            cmd += ["-e", "." + kw["extensions"].replace(",", ",.")]
        if kw.get("recursion"):
            cmd += ["-recursion", "-recursion-depth", kw.get("depth", "2")]
    elif fuzz_type == "2":
        param  = kw.get("param", "FUZZ")
        method = kw.get("method", "GET")
        cmd   += ["-u", kw.get("url", f"{target}/?{param}=FUZZ"), "-w", wordlist]
        if method.upper() == "POST":
            cmd += ["-X", "POST", "-d", f"{param}=FUZZ"]
    elif fuzz_type == "3":
        domain = target.replace("http://","").replace("https://","").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd   += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist, "-H", f"Host: FUZZ.{domain}"]
    elif fuzz_type == "4":
        cmd += ["-u", target, "-w", wordlist, "-H", "Host: FUZZ"]
    elif fuzz_type == "5":
        cmd += ["-u", kw.get("url", f"{target}/api/FUZZ"), "-w", wordlist]
    elif fuzz_type == "6":
        cmd += ["-u", kw.get("url", f"{target}/indexFUZZ"), "-w", wordlist]

    cmd += ["-t", kw.get("threads", p["threads"])]
    rate = kw.get("rate_limit") or p["rate"]
    if rate: cmd += ["-rate", str(rate)]

    f = kw.get("filters", {})
    if f.get("fc"): cmd += ["-fc", f["fc"]]
    if f.get("fs"): cmd += ["-fs", f["fs"]]
    if f.get("fw"): cmd += ["-fw", f["fw"]]
    if kw.get("header"): cmd += ["-H", f'"{kw["header"]}"']
    if kw.get("output"): cmd += ["-o", kw["output"], "-of", "csv"]
    if kw.get("extra"):  cmd.append(kw["extra"])
    cmd += ["-c"]
    return " ".join(cmd)


def build_feroxbuster(target, fuzz_type, wordlist, **kw):
    p   = kw.get("profile", PROFILES["3"])
    cmd = ["feroxbuster"]

    if fuzz_type == "1":
        cmd += ["-u", target, "-w", wordlist]
        if kw.get("extensions"):
            for ext in kw["extensions"].split(","):
                cmd += ["-x", ext.strip()]
        cmd += ["--depth", kw.get("depth","2") if kw.get("recursion") else "1"]
    elif fuzz_type == "2":
        cmd += ["-u", kw.get("url", f"{target}/?FUZZ=test"), "-w", wordlist, "--query"]
    elif fuzz_type == "3":
        domain = target.replace("http://","").replace("https://","").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd   += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist]
    elif fuzz_type == "4":
        cmd += ["-u", target, "-w", wordlist, "--headers", "Host: FUZZ"]
    else:
        cmd += ["-u", target, "-w", wordlist]

    cmd += ["-t", kw.get("threads", p["threads"])]
    rate = kw.get("rate_limit") or p["rate"]
    if rate: cmd += ["--rate-limit", str(rate)]

    f = kw.get("filters", {})
    if f.get("fc"):
        for code in f["fc"].split(","):
            cmd += ["--filter-status", code.strip()]
    if f.get("fs"): cmd += ["--filter-size",  f["fs"]]
    if f.get("fw"): cmd += ["--filter-words",  f["fw"]]
    if kw.get("header"): cmd += ["-H",  f'"{kw["header"]}"']
    if kw.get("output"): cmd += ["-o",  kw["output"]]
    if kw.get("extra"):  cmd.append(kw["extra"])
    return " ".join(cmd)


def build_wfuzz(target, fuzz_type, wordlist, **kw):
    p   = kw.get("profile", PROFILES["3"])
    cmd = ["wfuzz"]

    f = kw.get("filters", {})
    cmd += ["--hc", f["fc"]] if f.get("fc") else ["--hc", "404"]
    if f.get("fs"): cmd += ["--hs", f["fs"]]
    if f.get("fw"): cmd += ["--hw", f["fw"]]
    if p.get("wfuzz_delay"): cmd += ["--req-delay", p["wfuzz_delay"]]

    cmd += ["-w", wordlist, "-t", kw.get("threads", p["threads"])]

    if fuzz_type == "1":
        cmd += ["-u", kw.get("url", f"{target}/FUZZ")]
        if kw.get("extensions"):
            exts = kw["extensions"].split(",")
            cmd += ["-z", "list,{" + ",".join(f".{e.strip()}" for e in exts) + "}"]
    elif fuzz_type == "2":
        param  = kw.get("param", "FUZZ")
        method = kw.get("method", "GET")
        if method.upper() == "POST":
            cmd += ["-d", f"{param}=FUZZ", "-u", target]
        else:
            cmd += ["-u", f"{target}/?{param}=FUZZ"]
    elif fuzz_type == "3":
        domain = target.replace("http://","").replace("https://","").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd   += ["-H", f"Host: FUZZ.{domain}", "-u", f"{scheme}://{domain}"]
    elif fuzz_type == "4":
        cmd += ["-H", "Host: FUZZ", "-u", target]
    else:
        cmd += ["-u", kw.get("url", f"{target}/FUZZ")]

    if kw.get("header"): cmd += ["-H",  f'"{kw["header"]}"']
    if kw.get("output"): cmd += ["-f",  f"{kw['output']},raw"]
    if kw.get("extra"):  cmd.append(kw["extra"])
    return " ".join(cmd)


def build_gobuster(target, fuzz_type, wordlist, **kw):
    p   = kw.get("profile", PROFILES["3"])
    cmd = ["gobuster"]

    if fuzz_type == "1":
        cmd += ["dir", "-u", target, "-w", wordlist]
        if kw.get("extensions"): cmd += ["-x", kw["extensions"]]
    elif fuzz_type == "2":
        warn("gobuster doesn't support parameter fuzzing natively. Using dir mode.")
        cmd += ["dir", "-u", kw.get("url", target), "-w", wordlist]
    elif fuzz_type == "3":
        domain = target.replace("http://","").replace("https://","").split(":")[0]
        cmd   += ["dns", "-d", domain, "-w", wordlist]
    elif fuzz_type == "4":
        cmd += ["vhost", "-u", target, "-w", wordlist, "--append-domain"]
    elif fuzz_type == "5":
        cmd += ["dir", "-u", target, "-w", wordlist]
    elif fuzz_type == "6":
        cmd += ["dir", "-u", target, "-w", wordlist]
        if kw.get("extensions"): cmd += ["-x", kw["extensions"]]

    cmd += ["-t", kw.get("threads", p["threads"])]
    if p.get("delay_ms"): cmd += ["--delay", f"{p['delay_ms']}ms"]

    f = kw.get("filters", {})
    if f.get("fc"): cmd += ["--status-codes-blacklist", f["fc"]]
    if kw.get("header"): cmd += ["-H",  f'"{kw["header"]}"']
    if kw.get("output"): cmd += ["-o",  kw["output"]]
    if kw.get("extra"):  cmd.append(kw["extra"])
    return " ".join(cmd)


def build_dirsearch(target, fuzz_type, wordlist, **kw):
    p   = kw.get("profile", PROFILES["3"])
    cmd = ["dirsearch"]

    if fuzz_type == "1":
        cmd += ["-u", target, "-w", wordlist]
        cmd += ["-e", kw["extensions"]] if kw.get("extensions") else ["-e", "php,html,txt,js,json"]
    elif fuzz_type == "2":
        warn("dirsearch doesn't support parameter fuzzing. Using URL mode.")
        cmd += ["-u", kw.get("url", f"{target}/?FUZZ=test"), "-w", wordlist]
    elif fuzz_type == "3":
        warn("dirsearch is not ideal for subdomain fuzzing. Consider ffuf or wfuzz.")
        domain = target.replace("http://","").replace("https://","").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd   += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist]
    elif fuzz_type == "4":
        cmd += ["-u", target, "-w", wordlist, "-H", "Host: FUZZ"]
    else:
        cmd += ["-u", target, "-w", wordlist]
        if kw.get("extensions"): cmd += ["-e", kw["extensions"]]

    cmd += ["-t", kw.get("threads", p["threads"])]

    f = kw.get("filters", {})
    if f.get("fc"): cmd += ["--exclude-status", f["fc"]]
    if f.get("fs"): cmd += ["--exclude-sizes",  f["fs"]]
    if kw.get("header"): cmd += ["-H", f'"{kw["header"]}"']
    if kw.get("output"): cmd += ["-o", kw["output"]]
    if kw.get("extra"):  cmd.append(kw["extra"])
    return " ".join(cmd)


TOOL_BUILDERS = {
    "1": build_ffuf,
    "2": build_feroxbuster,
    "3": build_wfuzz,
    "4": build_gobuster,
    "5": build_dirsearch,
}

# ─── Manual Mode Option Gathering ─────────────────────────────────────────────

def gather_directory_options(tool_key, target, profile):
    wordlist   = ask_wordlist_directory()
    url        = prompt("URL with FUZZ placeholder", f"{target}/FUZZ", C.CYAN) if tool_key in ("1","3") else None
    extensions = ask_extensions()
    recursion  = False
    depth      = "2"
    if tool_key in ("1","2"):
        if prompt("Enable recursion? (y/N)", "n", C.CYAN).lower() == "y":
            recursion = True
            depth = prompt("Recursion depth", "2", C.CYAN)
    return dict(wordlist=wordlist, url=url, extensions=extensions, recursion=recursion,
                depth=depth, threads=ask_threads(profile), filters=ask_filter_options(),
                header=ask_headers(), rate_limit=ask_rate_limit(profile),
                output=ask_output_file(), extra=ask_extra_flags(), profile=profile)

def gather_parameter_options(tool_key, target, profile):
    wordlist = ask_wordlist_parameter()
    param    = prompt("Parameter name (or FUZZ)", "FUZZ", C.CYAN)
    method   = prompt("HTTP method (GET/POST)", "GET", C.CYAN).upper()
    url      = prompt("URL", f"{target}/?{param}=FUZZ" if method=="GET" else target, C.CYAN) if tool_key in ("1","3") else None
    return dict(wordlist=wordlist, param=param, method=method, url=url,
                threads=ask_threads(profile), filters=ask_filter_options(),
                header=ask_headers(), rate_limit=ask_rate_limit(profile),
                output=ask_output_file(), extra=ask_extra_flags(), profile=profile)

def gather_subdomain_options(tool_key, target, profile):
    return dict(wordlist=ask_wordlist_subdomain(), threads=ask_threads(profile),
                filters=ask_filter_options(), header=ask_headers(),
                rate_limit=ask_rate_limit(profile), output=ask_output_file(),
                extra=ask_extra_flags(), profile=profile)

def gather_vhost_options(tool_key, target, profile):
    return gather_subdomain_options(tool_key, target, profile)

def gather_api_options(tool_key, target, profile):
    wordlist = ask_wordlist_api()
    url      = prompt("API URL with FUZZ", f"{target}/api/FUZZ", C.CYAN) if tool_key in ("1","3") else None
    return dict(wordlist=wordlist, url=url, threads=ask_threads(profile),
                filters=ask_filter_options(), header=ask_headers(),
                rate_limit=ask_rate_limit(profile), output=ask_output_file(),
                extra=ask_extra_flags(), profile=profile)

def gather_extension_options(tool_key, target, profile):
    wordlist   = ask_wordlist_extension()
    url        = prompt("URL with FUZZ placeholder", f"{target}/indexFUZZ", C.CYAN) if tool_key in ("1","3") else None
    extensions = ask_extensions()
    return dict(wordlist=wordlist, url=url, extensions=extensions,
                threads=ask_threads(profile), filters=ask_filter_options(),
                header=ask_headers(), rate_limit=ask_rate_limit(profile),
                output=ask_output_file(), extra=ask_extra_flags(), profile=profile)

OPTION_GATHERERS = {
    "1": gather_directory_options,
    "2": gather_parameter_options,
    "3": gather_subdomain_options,
    "4": gather_vhost_options,
    "5": gather_api_options,
    "6": gather_extension_options,
}

# ─── Output Helpers ───────────────────────────────────────────────────────────

def print_command_box(cmd, profile):
    width  = max(len(cmd) + 4, 60)
    border = "═" * width

    print(f"\n{C.GREEN}{C.BOLD}")
    print(f"  ╔{border}╗")
    print(f"  ║{'  Generated Fuzzing Command':^{width}}║")
    print(f"  ╠{border}╣")

    parts = cmd.split(" ")
    line  = ""
    lines = []
    for p in parts:
        if len(line) + len(p) + 1 > width - 2:
            lines.append(line)
            line = "  " + p
        else:
            line += ("" if not line else " ") + p
    if line:
        lines.append(line)
    for ln in lines:
        print(f"  ║  {C.YELLOW}{ln:<{width-2}}{C.GREEN}║")
    print(f"  ╚{border}╝{C.RESET}")

    nice_prefix = profile.get("nice_prefix", "")
    if nice_prefix:
        run_cmd    = nice_prefix + cmd
        run_border = "─" * (len(run_cmd) + 4)
        print(f"""
  {C.CYAN}┌{run_border}┐{C.RESET}
  {C.CYAN}│{C.RESET}  {C.DIM}Run safely ({profile['name'].upper()} profile):{C.RESET}
  {C.CYAN}│{C.RESET}  {C.WHITE}{run_cmd}{C.RESET}
  {C.CYAN}└{run_border}┘{C.RESET}""")

    pname = profile["name"]
    if pname == "low":
        print(f"\n  {C.GREEN}✔  Low-Impact — rate-limited & nice'd. Browser stays usable.{C.RESET}")
    elif pname == "medium":
        print(f"\n  {C.YELLOW}✔  Medium — moderate speed. Some impact expected.{C.RESET}")
    else:
        print(f"\n  {C.RED}⚡  Full speed — close heavy apps before running.{C.RESET}")


def print_tips(tool_key, fuzz_type):
    tips = {
        ("1","1"): "Add '-mc all' to ffuf to show all status codes.",
        ("1","3"): "Use '-ac' in ffuf to auto-calibrate and remove false positives.",
        ("2","1"): "feroxbuster auto-detects 403/301 and can force-recurse.",
        ("3","1"): "wfuzz supports complex payloads with multiple -w flags.",
        ("4","3"): "gobuster DNS mode: add -r 8.8.8.8 to set a resolver.",
        ("5","1"): "dirsearch: use --proxy http://127.0.0.1:8080 for Burp.",
    }
    if (tool_key, fuzz_type) in tips:
        print(f"\n  {C.CYAN}💡 Tip: {tips[(tool_key, fuzz_type)]}{C.RESET}")
    if not check_tool_installed(TOOLS[tool_key]):
        warn(f"'{TOOLS[tool_key]}' not found in PATH. Install it before running.")


def maybe_run(cmd, tool_name, profile):
    print()
    if prompt("Run this command now? (y/N)", "n", C.GREEN).lower() == "y":
        if check_tool_installed(tool_name):
            full = profile.get("nice_prefix", "") + cmd
            print(f"\n  {C.YELLOW}Running:{C.RESET} {full}\n")
            os.system(full)
        else:
            warn(f"Cannot run: '{tool_name}' is not installed.")

# ─── QUICK MODE ───────────────────────────────────────────────────────────────

def run_quick():
    section("⚡ Quick Mode")
    print(f"  {C.DIM}Answer each prompt — ENTER keeps the default shown in [ ].{C.RESET}\n")
    print(f"  {C.DIM}{'─'*45}{C.RESET}\n")

    # target
    while True:
        raw = prompt("Target URL", color=C.CYAN)
        if not raw:
            warn("Target cannot be empty.")
            continue
        target = normalize_target(raw)
        break

    # tool
    print(f"\n  {C.DIM}Tools: ffuf · feroxbuster · wfuzz · gobuster · dirsearch  (or 1-5){C.RESET}")
    while True:
        raw      = prompt("Tool", "ffuf", C.CYAN).lower()
        tool_key = TOOL_ALIASES.get(raw) or (raw if raw in TOOLS else None)
        if tool_key: break
        print(f"  {C.RED}✗ Enter a tool name or number 1-5.{C.RESET}")

    # fuzz type
    print(f"\n  {C.DIM}Types: dir · param · sub · vhost · api · ext  (or 1-6){C.RESET}")
    while True:
        raw       = prompt("Fuzz type", "dir", C.CYAN).lower()
        fuzz_type = FUZZ_TYPE_ALIASES.get(raw) or (raw if raw in FUZZ_TYPES else None)
        if fuzz_type: break
        print(f"  {C.RED}✗ Enter a type name or number 1-6.{C.RESET}")

    # profile
    print(f"\n  {C.DIM}Profiles: low · medium · high  (or 1-3){C.RESET}")
    while True:
        raw         = prompt("Profile", "low", C.CYAN).lower()
        profile_key = PROFILE_ALIASES.get(raw) or (raw if raw in PROFILES else None)
        if profile_key:
            profile = PROFILES[profile_key]
            break
        print(f"  {C.RED}✗ Enter low / medium / high (or 1-3).{C.RESET}")

    print(f"\n  {C.DIM}{'─'*45}{C.RESET}\n")

    # wordlist
    default_wl = TYPE_DEFAULT_WORDLIST[fuzz_type]
    wl_raw     = prompt("Wordlist (ENTER for default)", default_wl, C.CYAN)
    wordlist   = wl_raw if wl_raw else default_wl

    # extensions
    extensions = ask_extensions()

    # threads & rate
    threads  = prompt("Threads", profile["threads"], C.CYAN)
    rate_raw = prompt("Rate limit req/s (0 = no limit)", profile["rate"] or "0", C.CYAN)
    rate     = rate_raw if rate_raw and rate_raw != "0" else None

    # filter codes
    fc_raw  = prompt("Hide status codes (e.g. 404,403 — ENTER to skip)", "", C.CYAN)
    filters = {"fc": fc_raw} if fc_raw else {}

    # header & output
    header     = ask_headers()
    output_raw = prompt("Output file (ENTER to skip)", "", C.CYAN)
    output     = output_raw if output_raw else None

    # extra
    extra = ask_extra_flags()

    # build & print
    section("Generated Command")
    builder = TOOL_BUILDERS[tool_key]
    cmd = builder(
        target, fuzz_type, wordlist,
        threads=threads, rate_limit=rate, filters=filters,
        extensions=extensions, header=header, output=output,
        extra=extra, profile=profile,
    )
    print_command_box(cmd, profile)
    print_tips(tool_key, fuzz_type)
    maybe_run(cmd, TOOLS[tool_key], profile)

# ─── MANUAL MODE ──────────────────────────────────────────────────────────────

def run_manual():
    profile = select_profile()

    section("Step 1: Select Fuzzing Tool")
    tool_key = choose("Which tool?", TOOLS)
    success(f"Selected: {TOOLS[tool_key]}")

    section("Step 2: Enter Target")
    info("Example: http://192.168.1.10:8080  |  https://target.com")
    while True:
        raw = prompt("Target (IP or domain with optional port)", color=C.CYAN)
        if not raw:
            warn("Target cannot be empty.")
            continue
        if not validate_url(raw):
            warn("Target should start with http:// or https://")
            if prompt("Prepend http://?  (y/N)", "y", C.CYAN).lower() == "y":
                raw = "http://" + raw
        target = raw.rstrip("/")
        success(f"Target: {target}")
        break

    section("Step 3: Select Fuzzing Type")
    fuzz_type = choose("What kind of fuzzing?", FUZZ_TYPES)
    success(f"Fuzzing type: {FUZZ_TYPES[fuzz_type]}")

    section("Step 4: Configure Options")
    opts     = OPTION_GATHERERS[fuzz_type](tool_key, target, profile)
    wordlist = opts.pop("wordlist")

    section("Step 5: Generated Command")
    cmd = TOOL_BUILDERS[tool_key](target, fuzz_type, wordlist, **opts)
    print_command_box(cmd, profile)
    print_tips(tool_key, fuzz_type)
    maybe_run(cmd, TOOLS[tool_key], profile)

# ─── Entry Point ──────────────────────────────────────────────────────────────

def run():
    banner()
    mode = select_mode()

    if mode == "1":
        run_quick()
    else:
        run_manual()

    print()
    if prompt("Generate another command? (y/N)", "n", C.CYAN).lower() == "y":
        run()
    else:
        print(f"\n{C.GREEN}{C.BOLD}  Happy Fuzzing! 🎯{C.RESET}\n")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}  Interrupted. Goodbye!{C.RESET}\n")
        sys.exit(0)

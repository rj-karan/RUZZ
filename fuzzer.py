#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║         Web CTF Fuzzing Command Generator            ║
║         Supports: ffuf, feroxbuster, wfuzz,          ║
║                   gobuster, dirsearch                ║
╚══════════════════════════════════════════════════════╝
"""

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
    # Computer block centered for 80-col terminal (11 space offset)
    # RUZZ lines centered inside 54-char inner screen (10 left, 11 right padding)
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

# ─── Base path ────────────────────────────────────────────────────────────────

WC = "/usr/share/seclists/Discovery/Web-Content"
DNS = "/usr/share/seclists/Discovery/DNS"

# ─── SecLists Wordlist Defaults ───────────────────────────────────────────────

WORDLISTS = {
    # Directory fuzzing
    "directory":                f"{WC}/common.txt",
    "directory_medium":         f"{WC}/raft-medium-directories.txt",
    "directory_large":          f"{WC}/raft-large-directories.txt",
    "directory_small":          f"{WC}/raft-small-directories.txt",
    "directory_dirbuster_med":  f"{WC}/DirBuster-2007_directory-list-2.3-medium.txt",
    "directory_dirbuster_big":  f"{WC}/DirBuster-2007_directory-list-2.3-big.txt",
    "directory_combined":       f"{WC}/combined_directories.txt",

    # File fuzzing
    "files_medium":             f"{WC}/raft-medium-files.txt",
    "files_large":              f"{WC}/raft-large-files.txt",
    "files_small":              f"{WC}/raft-small-files.txt",

    # Word fuzzing
    "words_medium":             f"{WC}/raft-medium-words.txt",
    "words_large":              f"{WC}/raft-large-words.txt",

    # Extensions
    "extensions":               f"{WC}/web-extensions.txt",
    "extensions_big":           f"{WC}/web-extensions-big.txt",

    # Parameters
    "parameter":                f"{WC}/burp-parameter-names.txt",
    "url_params":               f"{WC}/url-params_from-top-55-most-popular-apps.txt",

    # Subdomains / DNS
    "subdomain":                f"{DNS}/subdomains-top1million-5000.txt",
    "subdomain_large":          f"{DNS}/subdomains-top1million-20000.txt",

    # VHOST (reuse subdomain list)
    "vhost":                    f"{DNS}/subdomains-top1million-5000.txt",

    # API
    "api":                      f"{WC}/common-api-endpoints-mazen160.txt",
    "api_graphql":              f"{WC}/graphql.txt",

    # Quick hits / misc
    "quickhits":                f"{WC}/quickhits.txt",
    "big":                      f"{WC}/big.txt",
}

FUZZ_TYPES = {
    "1": "Directory/Subdirectory Fuzzing",
    "2": "Parameter Fuzzing",
    "3": "Subdomain Fuzzing",
    "4": "VHOST Fuzzing",
    "5": "API Endpoint Fuzzing",
    "6": "File Extension Fuzzing",
}

TOOLS = {
    "1": "ffuf",
    "2": "feroxbuster",
    "3": "wfuzz",
    "4": "gobuster",
    "5": "dirsearch",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def prompt(msg, default=None, color=C.CYAN):
    """Display a styled prompt and return user input."""
    suffix = f"{C.DIM} [{default}]{C.RESET}" if default else ""
    val = input(f"{color}{C.BOLD}  ➜ {C.RESET}{color}{msg}{suffix}{C.RESET}: ").strip()
    return val if val else default

def choose(msg, options: dict, color=C.YELLOW):
    """Display a numbered menu and return the chosen key."""
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
    """Print a section divider."""
    print(f"\n{C.BLUE}{'─'*55}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.BLUE}{'─'*55}{C.RESET}")

def warn(msg):
    print(f"  {C.YELLOW}⚠  {msg}{C.RESET}")

def info(msg):
    print(f"  {C.DIM}ℹ  {msg}{C.RESET}")

def success(msg):
    print(f"  {C.GREEN}✔  {msg}{C.RESET}")

def check_tool_installed(tool):
    """Check if the tool binary exists in PATH."""
    return shutil.which(tool) is not None

def validate_url(url):
    """Basic URL validation."""
    pattern = re.compile(r'^https?://.+', re.IGNORECASE)
    return bool(pattern.match(url))

def ask_wordlist_directory():
    """Present all directory wordlist options for the user to choose."""
    options = {
        "1": ("common",              WORDLISTS["directory"]),
        "2": ("raft-medium-dirs",    WORDLISTS["directory_medium"]),
        "3": ("raft-large-dirs",     WORDLISTS["directory_large"]),
        "4": ("raft-small-dirs",     WORDLISTS["directory_small"]),
        "5": ("dirbuster-medium",    WORDLISTS["directory_dirbuster_med"]),
        "6": ("dirbuster-big",       WORDLISTS["directory_dirbuster_big"]),
        "7": ("combined-dirs",       WORDLISTS["directory_combined"]),
        "8": ("big",                 WORDLISTS["big"]),
        "9": ("quickhits",           WORDLISTS["quickhits"]),
        "c": ("custom path",         None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Directory Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<25} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["directory"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_files():
    """Present file-focused wordlist options."""
    options = {
        "1": ("raft-medium-files",  WORDLISTS["files_medium"]),
        "2": ("raft-large-files",   WORDLISTS["files_large"]),
        "3": ("raft-small-files",   WORDLISTS["files_small"]),
        "4": ("raft-medium-words",  WORDLISTS["words_medium"]),
        "5": ("raft-large-words",   WORDLISTS["words_large"]),
        "c": ("custom path",        None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}File Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<25} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["files_medium"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_parameter():
    """Present parameter wordlist options."""
    options = {
        "1": ("burp-parameter-names",          WORDLISTS["parameter"]),
        "2": ("url-params-top55-apps",          WORDLISTS["url_params"]),
        "c": ("custom path",                   None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Parameter Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["parameter"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_subdomain():
    """Present subdomain wordlist options."""
    options = {
        "1": ("subdomains-top1million-5000",   WORDLISTS["subdomain"]),
        "2": ("subdomains-top1million-20000",  WORDLISTS["subdomain_large"]),
        "c": ("custom path",                   None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Subdomain Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["subdomain"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_api():
    """Present API wordlist options."""
    options = {
        "1": ("common-api-endpoints-mazen160",  WORDLISTS["api"]),
        "2": ("graphql",                         WORDLISTS["api_graphql"]),
        "3": ("raft-medium-words",               WORDLISTS["words_medium"]),
        "c": ("custom path",                     None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}API Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<35} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["api"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_wordlist_extension():
    """Present extension wordlist options."""
    options = {
        "1": ("web-extensions",      WORDLISTS["extensions"]),
        "2": ("web-extensions-big",  WORDLISTS["extensions_big"]),
        "c": ("custom path",         None),
    }
    print(f"\n  {C.MAGENTA}{C.BOLD}Extension Wordlist:{C.RESET}")
    for k, (label, path) in options.items():
        display = path if path else "enter manually"
        print(f"  {C.DIM}{k}{C.RESET}) {label:<25} {C.CYAN}{display}{C.RESET}")
    while True:
        sel = prompt("Choose wordlist", "1", color=C.MAGENTA)
        if sel in options:
            _, path = options[sel]
            if path is None:
                return prompt("Enter custom wordlist path", WORDLISTS["extensions"], C.MAGENTA)
            return path
        print(f"  {C.RED}✗ Invalid. Try again.{C.RESET}")

def ask_extensions():
    """Ask user for file extensions to fuzz."""
    raw = prompt("Extensions to fuzz (comma-separated, e.g. php,txt,html) or ENTER to skip", "", C.CYAN)
    if raw:
        exts = ",".join(e.strip().lstrip(".") for e in raw.split(","))
        return exts
    return None

def ask_threads(default="40"):
    return prompt("Number of threads", default, C.CYAN)

def ask_rate_limit():
    raw = prompt("Rate limit (requests/sec, ENTER to skip)", "", C.CYAN)
    return raw if raw else None

def ask_extra_flags():
    raw = prompt("Extra flags to append (ENTER to skip)", "", C.CYAN)
    return raw if raw else ""

def ask_headers():
    """Ask for optional custom headers."""
    raw = prompt("Custom headers (e.g. 'Cookie: session=abc', ENTER to skip)", "", C.CYAN)
    return raw if raw else None

def ask_filter_options(tool):
    """Ask for response filtering options."""
    print(f"\n  {C.MAGENTA}{C.BOLD}Response Filtering (optional):{C.RESET}")
    filters = {}

    fc = prompt("Filter by HTTP status codes (e.g. 404,403 to hide, ENTER to skip)", "", C.CYAN)
    if fc:
        filters["fc"] = fc

    fs = prompt("Filter by response size in bytes (ENTER to skip)", "", C.CYAN)
    if fs:
        filters["fs"] = fs

    fw = prompt("Filter by word count (ENTER to skip)", "", C.CYAN)
    if fw:
        filters["fw"] = fw

    return filters

def ask_output_file():
    """Ask whether to save output."""
    save = prompt("Save output to file? (y/N)", "n", C.CYAN).lower()
    if save == "y":
        return prompt("Output file path", "fuzz_output.txt", C.CYAN)
    return None

# ─── Per-Tool Command Builders ────────────────────────────────────────────────

def build_ffuf(target, fuzz_type, wordlist, **kwargs):
    cmd_parts = ["ffuf"]

    if fuzz_type == "1":   # Directory
        url = kwargs.get("url", f"{target}/FUZZ")
        cmd_parts += ["-u", url, "-w", wordlist]
        if kwargs.get("extensions"):
            exts = "." + kwargs["extensions"].replace(",", ",.")
            cmd_parts += ["-e", exts]
        if kwargs.get("recursion"):
            cmd_parts += ["-recursion", "-recursion-depth", kwargs.get("depth", "2")]

    elif fuzz_type == "2":  # Parameter
        param = kwargs.get("param", "FUZZ")
        method = kwargs.get("method", "GET")
        url = kwargs.get("url", f"{target}/?{param}=FUZZ")
        cmd_parts += ["-u", url, "-w", wordlist]
        if method.upper() == "POST":
            cmd_parts += ["-X", "POST", "-d", f"{param}=FUZZ"]

    elif fuzz_type == "3":  # Subdomain
        domain = target.replace("http://", "").replace("https://", "").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd_parts += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist,
                       "-H", f"Host: FUZZ.{domain}"]

    elif fuzz_type == "4":  # VHOST
        cmd_parts += ["-u", target, "-w", wordlist, "-H", "Host: FUZZ"]

    elif fuzz_type == "5":  # API
        url = kwargs.get("url", f"{target}/api/FUZZ")
        cmd_parts += ["-u", url, "-w", wordlist]

    elif fuzz_type == "6":  # Extension
        url = kwargs.get("url", f"{target}/indexFUZZ")
        cmd_parts += ["-u", url, "-w", wordlist]

    cmd_parts += ["-t", kwargs.get("threads", "40")]

    filters = kwargs.get("filters", {})
    if filters.get("fc"):
        cmd_parts += ["-fc", filters["fc"]]
    if filters.get("fs"):
        cmd_parts += ["-fs", filters["fs"]]
    if filters.get("fw"):
        cmd_parts += ["-fw", filters["fw"]]

    if kwargs.get("header"):
        cmd_parts += ["-H", f'"{kwargs["header"]}"']
    if kwargs.get("rate_limit"):
        cmd_parts += ["-rate", kwargs["rate_limit"]]
    if kwargs.get("output"):
        cmd_parts += ["-o", kwargs["output"], "-of", "csv"]
    if kwargs.get("extra"):
        cmd_parts.append(kwargs["extra"])

    cmd_parts += ["-c"]
    return " ".join(cmd_parts)


def build_feroxbuster(target, fuzz_type, wordlist, **kwargs):
    cmd_parts = ["feroxbuster"]

    if fuzz_type == "1":   # Directory
        cmd_parts += ["-u", target, "-w", wordlist]
        if kwargs.get("extensions"):
            for ext in kwargs["extensions"].split(","):
                cmd_parts += ["-x", ext.strip()]
        if kwargs.get("recursion"):
            cmd_parts += ["--depth", kwargs.get("depth", "2")]
        else:
            cmd_parts += ["--depth", "1"]

    elif fuzz_type == "2":  # Parameter
        url = kwargs.get("url", f"{target}/?FUZZ=test")
        cmd_parts += ["-u", url, "-w", wordlist, "--query"]

    elif fuzz_type == "3":  # Subdomain
        domain = target.replace("http://", "").replace("https://", "").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd_parts += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist]

    elif fuzz_type == "4":  # VHOST
        cmd_parts += ["-u", target, "-w", wordlist, "--headers", "Host: FUZZ"]

    elif fuzz_type in ("5", "6"):
        cmd_parts += ["-u", target, "-w", wordlist]

    cmd_parts += ["-t", kwargs.get("threads", "40")]

    filters = kwargs.get("filters", {})
    if filters.get("fc"):
        for code in filters["fc"].split(","):
            cmd_parts += ["--filter-status", code.strip()]
    if filters.get("fs"):
        cmd_parts += ["--filter-size", filters["fs"]]
    if filters.get("fw"):
        cmd_parts += ["--filter-words", filters["fw"]]

    if kwargs.get("header"):
        cmd_parts += ["-H", f'"{kwargs["header"]}"']
    if kwargs.get("rate_limit"):
        cmd_parts += ["--rate-limit", kwargs["rate_limit"]]
    if kwargs.get("output"):
        cmd_parts += ["-o", kwargs["output"]]
    if kwargs.get("extra"):
        cmd_parts.append(kwargs["extra"])

    cmd_parts += ["--color"]
    return " ".join(cmd_parts)


def build_wfuzz(target, fuzz_type, wordlist, **kwargs):
    cmd_parts = ["wfuzz"]

    filters = kwargs.get("filters", {})
    if filters.get("fc"):
        cmd_parts += ["--hc", filters["fc"]]
    else:
        cmd_parts += ["--hc", "404"]
    if filters.get("fs"):
        cmd_parts += ["--hs", filters["fs"]]
    if filters.get("fw"):
        cmd_parts += ["--hw", filters["fw"]]

    cmd_parts += ["-w", wordlist]
    cmd_parts += ["-t", kwargs.get("threads", "40")]

    if fuzz_type == "1":   # Directory
        url = kwargs.get("url", f"{target}/FUZZ")
        cmd_parts += ["-u", url]
        if kwargs.get("extensions"):
            exts = kwargs["extensions"].split(",")
            ext_pattern = "{" + ",".join(f".{e.strip()}" for e in exts) + "}"
            cmd_parts += ["-z", f"list,{ext_pattern}"]

    elif fuzz_type == "2":  # Parameter
        param = kwargs.get("param", "FUZZ")
        method = kwargs.get("method", "GET")
        if method.upper() == "POST":
            cmd_parts += ["-d", f"{param}=FUZZ", "-u", target]
        else:
            cmd_parts += ["-u", f"{target}/?{param}=FUZZ"]

    elif fuzz_type == "3":  # Subdomain
        domain = target.replace("http://", "").replace("https://", "").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd_parts += ["-H", f"Host: FUZZ.{domain}", "-u", f"{scheme}://{domain}"]

    elif fuzz_type == "4":  # VHOST
        cmd_parts += ["-H", "Host: FUZZ", "-u", target]

    elif fuzz_type in ("5", "6"):
        url = kwargs.get("url", f"{target}/FUZZ")
        cmd_parts += ["-u", url]

    if kwargs.get("header"):
        cmd_parts += ["-H", f'"{kwargs["header"]}"']
    if kwargs.get("output"):
        cmd_parts += ["-f", f"{kwargs['output']},raw"]
    if kwargs.get("extra"):
        cmd_parts.append(kwargs["extra"])

    return " ".join(cmd_parts)


def build_gobuster(target, fuzz_type, wordlist, **kwargs):
    cmd_parts = ["gobuster"]

    if fuzz_type == "1":   # Directory
        cmd_parts += ["dir", "-u", target, "-w", wordlist]
        if kwargs.get("extensions"):
            cmd_parts += ["-x", kwargs["extensions"]]

    elif fuzz_type == "2":  # Parameter
        warn("gobuster doesn't natively support parameter fuzzing. Using dir mode as fallback.")
        cmd_parts += ["dir", "-u", kwargs.get("url", target), "-w", wordlist]

    elif fuzz_type == "3":  # Subdomain (DNS mode)
        domain = target.replace("http://", "").replace("https://", "").split(":")[0]
        cmd_parts += ["dns", "-d", domain, "-w", wordlist]

    elif fuzz_type == "4":  # VHOST
        cmd_parts += ["vhost", "-u", target, "-w", wordlist, "--append-domain"]

    elif fuzz_type == "5":  # API
        cmd_parts += ["dir", "-u", target, "-w", wordlist]

    elif fuzz_type == "6":  # Extension
        cmd_parts += ["dir", "-u", target, "-w", wordlist]
        if kwargs.get("extensions"):
            cmd_parts += ["-x", kwargs["extensions"]]

    cmd_parts += ["-t", kwargs.get("threads", "40")]

    filters = kwargs.get("filters", {})
    if filters.get("fc"):
        cmd_parts += ["--status-codes-blacklist", filters["fc"]]

    if kwargs.get("header"):
        cmd_parts += ["-H", f'"{kwargs["header"]}"']
    if kwargs.get("rate_limit"):
        cmd_parts += ["--delay", f"{kwargs['rate_limit']}ms"]
    if kwargs.get("output"):
        cmd_parts += ["-o", kwargs["output"]]
    if kwargs.get("extra"):
        cmd_parts.append(kwargs["extra"])

    return " ".join(cmd_parts)


def build_dirsearch(target, fuzz_type, wordlist, **kwargs):
    cmd_parts = ["dirsearch"]

    if fuzz_type == "1":   # Directory
        cmd_parts += ["-u", target, "-w", wordlist]
        if kwargs.get("extensions"):
            cmd_parts += ["-e", kwargs["extensions"]]
        else:
            cmd_parts += ["-e", "php,html,txt,js,json"]

    elif fuzz_type == "2":  # Parameter
        warn("dirsearch doesn't natively support parameter fuzzing. Using URL mode.")
        url = kwargs.get("url", f"{target}/?FUZZ=test")
        cmd_parts += ["-u", url, "-w", wordlist]

    elif fuzz_type == "3":  # Subdomain
        warn("dirsearch is not ideal for subdomain fuzzing. Consider using ffuf or wfuzz.")
        domain = target.replace("http://", "").replace("https://", "").split(":")[0]
        scheme = "https" if "https" in target else "http"
        cmd_parts += ["-u", f"{scheme}://FUZZ.{domain}", "-w", wordlist]

    elif fuzz_type == "4":  # VHOST
        cmd_parts += ["-u", target, "-w", wordlist, "-H", "Host: FUZZ"]

    elif fuzz_type in ("5", "6"):
        cmd_parts += ["-u", target, "-w", wordlist]
        if kwargs.get("extensions"):
            cmd_parts += ["-e", kwargs["extensions"]]

    cmd_parts += ["-t", kwargs.get("threads", "40")]

    filters = kwargs.get("filters", {})
    if filters.get("fc"):
        cmd_parts += ["--exclude-status", filters["fc"]]
    if filters.get("fs"):
        cmd_parts += ["--exclude-sizes", filters["fs"]]

    if kwargs.get("header"):
        cmd_parts += ["-H", f'"{kwargs["header"]}"']
    if kwargs.get("output"):
        cmd_parts += ["-o", kwargs["output"]]
    if kwargs.get("extra"):
        cmd_parts.append(kwargs["extra"])

    return " ".join(cmd_parts)


TOOL_BUILDERS = {
    "1": build_ffuf,
    "2": build_feroxbuster,
    "3": build_wfuzz,
    "4": build_gobuster,
    "5": build_dirsearch,
}

# ─── Fuzz-Type-Specific Option Gathering ─────────────────────────────────────

def gather_directory_options(tool_key, target):
    wordlist = ask_wordlist_directory()

    url = None
    if tool_key in ("1", "3"):
        url = prompt("URL with FUZZ placeholder", f"{target}/FUZZ", C.CYAN)

    extensions = ask_extensions()

    recursion = False
    depth = "2"
    if tool_key in ("1", "2"):
        r = prompt("Enable recursion? (y/N)", "n", C.CYAN).lower()
        recursion = (r == "y")
        if recursion:
            depth = prompt("Recursion depth", "2", C.CYAN)

    threads = ask_threads()
    filters = ask_filter_options(TOOLS[tool_key])
    header  = ask_headers()
    rate    = ask_rate_limit()
    output  = ask_output_file()
    extra   = ask_extra_flags()

    return dict(wordlist=wordlist, url=url, extensions=extensions, recursion=recursion,
                depth=depth, threads=threads, filters=filters,
                header=header, rate_limit=rate, output=output, extra=extra)


def gather_parameter_options(tool_key, target):
    wordlist = ask_wordlist_parameter()
    param    = prompt("Parameter name (or FUZZ)", "FUZZ", C.CYAN)
    method   = prompt("HTTP method (GET/POST)", "GET", C.CYAN).upper()
    url = None
    if tool_key in ("1", "3"):
        default_url = f"{target}/?{param}=FUZZ" if method == "GET" else target
        url = prompt("URL", default_url, C.CYAN)

    threads  = ask_threads()
    filters  = ask_filter_options(TOOLS[tool_key])
    header   = ask_headers()
    output   = ask_output_file()
    extra    = ask_extra_flags()

    return dict(wordlist=wordlist, param=param, method=method, url=url, threads=threads,
                filters=filters, header=header, output=output, extra=extra)


def gather_subdomain_options(tool_key, target):
    wordlist = ask_wordlist_subdomain()
    threads  = ask_threads()
    filters  = ask_filter_options(TOOLS[tool_key])
    header   = ask_headers()
    output   = ask_output_file()
    extra    = ask_extra_flags()

    return dict(wordlist=wordlist, threads=threads, filters=filters,
                header=header, output=output, extra=extra)


def gather_vhost_options(tool_key, target):
    wordlist = ask_wordlist_subdomain()   # same DNS lists work for VHOST
    threads  = ask_threads()
    filters  = ask_filter_options(TOOLS[tool_key])
    header   = ask_headers()
    output   = ask_output_file()
    extra    = ask_extra_flags()

    return dict(wordlist=wordlist, threads=threads, filters=filters,
                header=header, output=output, extra=extra)


def gather_api_options(tool_key, target):
    wordlist = ask_wordlist_api()
    url = None
    if tool_key in ("1", "3"):
        url = prompt("API base URL with FUZZ", f"{target}/api/FUZZ", C.CYAN)
    threads  = ask_threads()
    filters  = ask_filter_options(TOOLS[tool_key])
    header   = ask_headers()
    output   = ask_output_file()
    extra    = ask_extra_flags()

    return dict(wordlist=wordlist, url=url, threads=threads, filters=filters,
                header=header, output=output, extra=extra)


def gather_extension_options(tool_key, target):
    wordlist = ask_wordlist_extension()
    url = None
    if tool_key in ("1", "3"):
        url = prompt("URL with FUZZ placeholder (e.g. target/indexFUZZ)", f"{target}/indexFUZZ", C.CYAN)
    extensions = ask_extensions()
    threads    = ask_threads()
    filters    = ask_filter_options(TOOLS[tool_key])
    header     = ask_headers()
    output     = ask_output_file()
    extra      = ask_extra_flags()

    return dict(wordlist=wordlist, url=url, extensions=extensions, threads=threads, filters=filters,
                header=header, output=output, extra=extra)


OPTION_GATHERERS = {
    "1": gather_directory_options,
    "2": gather_parameter_options,
    "3": gather_subdomain_options,
    "4": gather_vhost_options,
    "5": gather_api_options,
    "6": gather_extension_options,
}

# ─── Main Flow ────────────────────────────────────────────────────────────────

def print_command_box(cmd, tool_name):
    """Pretty-print the final command in a highlighted box."""
    width = max(len(cmd) + 4, 60)
    border = "═" * width

    print(f"\n{C.GREEN}{C.BOLD}")
    print(f"  ╔{border}╗")
    print(f"  ║{'  Generated Fuzzing Command':^{width}}║")
    print(f"  ╠{border}╣")

    parts = cmd.split(" ")
    line = ""
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


def print_tips(tool_key, fuzz_type):
    """Print quick usage tips."""
    tips = {
        ("1", "1"): "Tip: Add '-mc all' to ffuf to show all status codes.",
        ("1", "3"): "Tip: Use '-ac' in ffuf to auto-calibrate and remove false positives.",
        ("2", "1"): "Tip: feroxbuster auto-detects 403/301 and can force-recurse.",
        ("3", "1"): "Tip: wfuzz supports complex payloads with multiple -w flags.",
        ("4", "3"): "Tip: gobuster DNS mode requires a valid resolver; add -r 8.8.8.8.",
        ("5", "1"): "Tip: dirsearch supports proxy via --proxy http://127.0.0.1:8080.",
    }
    key = (tool_key, fuzz_type)
    if key in tips:
        print(f"\n  {C.CYAN}💡 {tips[key]}{C.RESET}")

    tool_name = TOOLS[tool_key]
    if not check_tool_installed(tool_name):
        warn(f"'{tool_name}' was not found in your PATH. Install it before running the command.")


def run():
    banner()

    section("Step 1: Select Fuzzing Tool")
    tool_key = choose("Which tool do you want to use?", TOOLS)
    tool_name = TOOLS[tool_key]
    success(f"Selected: {tool_name}")

    section("Step 2: Enter Target")
    info("Example: http://192.168.1.10:8080  |  https://target.com")
    while True:
        target = prompt("Enter target (IP or domain with optional port)", color=C.CYAN)
        if not target:
            warn("Target cannot be empty.")
            continue
        if not validate_url(target):
            warn("Target should start with http:// or https://")
            fix = prompt("Prepend http://?  (y/N)", "y", C.CYAN).lower()
            if fix == "y":
                target = "http://" + target
        target = target.rstrip("/")
        success(f"Target: {target}")
        break

    section("Step 3: Select Fuzzing Type")
    fuzz_type = choose("What kind of fuzzing?", FUZZ_TYPES)
    success(f"Fuzzing type: {FUZZ_TYPES[fuzz_type]}")

    section("Step 4: Configure Options")
    gatherer = OPTION_GATHERERS[fuzz_type]
    opts     = gatherer(tool_key, target)

    section("Step 5: Generated Command")
    builder  = TOOL_BUILDERS[tool_key]
    wordlist = opts.pop("wordlist")

    cmd = builder(target, fuzz_type, wordlist, **opts)
    print_command_box(cmd, tool_name)
    print_tips(tool_key, fuzz_type)

    print()
    run_now = prompt("Run this command now? (y/N)", "n", C.GREEN).lower()
    if run_now == "y":
        if check_tool_installed(tool_name):
            print(f"\n  {C.YELLOW}Running...{C.RESET}\n")
            os.system(cmd)
        else:
            warn(f"Cannot run: '{tool_name}' is not installed.")

    print()
    again = prompt("Generate another command? (y/N)", "n", C.CYAN).lower()
    if again == "y":
        run()
    else:
        print(f"\n{C.GREEN}{C.BOLD}  Happy Fuzzing! 🎯{C.RESET}\n")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}  Interrupted. Goodbye!{C.RESET}\n")
        sys.exit(0)
# 🎯 RUZZ — Web CTF Fuzzing Command Generator

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![CTF Tool](https://img.shields.io/badge/CTF-Tool-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20ParrotOS-informational?style=for-the-badge)

A beginner-friendly, interactive CLI tool that generates copy-paste ready fuzzing commands for the most popular web CTF tools.  
Stop googling flags — just answer the prompts and get your command.

---

## ✨ Features

- 🛠️ **5 tools supported** — ffuf, feroxbuster, wfuzz, gobuster, dirsearch
- 🔍 **6 fuzzing modes** — Directory, Parameter, Subdomain, VHOST, API Endpoint, File Extension
- ⚡ **Quick mode** — single screen, rapid-fire prompts, instant command output
- 🗺️ **Manual mode** — step-by-step guided flow (great for beginners)
- 🐢 **Resource Impact Profiles** — Low / Medium / High so fuzzing never kills your browser
- 📚 **Auto-suggests SecLists wordlists** based on your chosen fuzzing type
- 🎨 **Color-coded interactive UI** with step-by-step prompts
- 🔁 **Recursion support** with configurable depth (ffuf & feroxbuster)
- 🧵 **Thread count pre-filled per profile** — override if you want
- 🚦 **Rate limiting baked in** — per-tool flags applied automatically
- 🔎 **Response filtering** — filter by HTTP status code, response size, or word count
- 📝 **Output file support** in the correct format per tool
- 🪄 **Custom headers** support (e.g. `Cookie`, `Authorization`)
- ⚠️ **Detects if a tool is not installed** in your PATH
- 🔄 **Loop mode** — generate multiple commands without restarting

---

## ⚙️ Resource Impact Profiles

One of the biggest pain points with fuzzing is that it **saturates your CPU and network**, making your browser and other apps freeze.

RUZZ fixes this by asking you to pick a profile **before** anything else:

| Profile | Threads | Rate Limit | `nice` level | Effect |
|---------|---------|------------|--------------|--------|
| 🟢 **Low Impact** | 5 | 30 req/s | `nice -n 19` | Browser stays fully usable |
| 🟡 **Medium** | 20 | 80 req/s | `nice -n 10` | Balanced — some slowdown |
| 🔴 **High / Full Speed** | 40 | None | No nice | Max speed, PC may freeze |

The profile is automatically applied to every tool's command using the correct flag for that tool:

| Tool | Rate limit flag | Delay flag |
|------|----------------|------------|
| ffuf | `-rate 30` | — |
| feroxbuster | `--rate-limit 30` | — |
| gobuster | — | `--delay 30ms` |
| wfuzz | `--req-delay 0.03` | — |
| dirsearch | *(threads only)* | — |

When you choose to run the command directly from the tool, it is automatically prefixed with `nice -n 19` (or `nice -n 10` for Medium).

---

## 🧠 What is `nice`?

`nice` is a Linux command that sets the **CPU scheduling priority** of a process.

Every process has a niceness value from **-20** (highest priority) to **+19** (lowest priority). Your browser and terminal run at `0` by default.

```
-20  ←── highest priority (greedy)
  0  ←── default for everything
+19  ←── lowest priority (runs only when nothing else needs CPU)
```

Running your fuzzer at `nice -n 19` means:

> The kernel gives CPU to your browser, editor, and terminal first.  
> The fuzzer gets whatever is left over.

**On an idle machine** — barely slower. The CPU is free anyway.  
**While browsing** — slightly slower fuzzing, but a fully usable machine.

```bash
# Run manually with low CPU priority
nice -n 19 ffuf -u http://target/FUZZ -w wordlist.txt -rate 30

# Change priority of an already-running process
renice +19 -p $(pgrep ffuf)

# Check niceness of a running process
ps -o pid,ni,comm -p $(pgrep ffuf)
```

`nice` controls **CPU**. Rate limiting (`-rate`) controls **network**. You need both for a fully smooth experience — that is why v2.1 applies both together.

---

## 🖥️ Demo

```
           ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
           ┃          ██████╗ ██╗   ██╗███████╗███████╗           ┃
           ┃          ██╔══██╗██║   ██║╚══███╔╝╚══███╔╝           ┃
           ┃          ██████╔╝██║   ██║  ███╔╝   ███╔╝            ┃
           ┃          ██╔══██╗██║   ██║ ███╔╝   ███╔╝             ┃
           ┃          ██║  ██║╚██████╔╝███████╗███████╗           ┃
           ┃          ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝           ┃
           ┃         ▸ web ctf fuzzing command generator           ┃
           ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  How do you want to build your command?
  ───────────────────────────────────────
  1) ⚡ Quick   — single screen, rapid-fire prompts, instant command
  2) ▸ Manual  — step-by-step guided mode (better for beginners)

── Quick Mode ─────────────────────────────────────────
  ➜ Target URL          : http://10.10.10.10
  ➜ Tool   [ffuf]       :
  ➜ Fuzz type  [dir]    :
  ➜ Profile    [low]    :
  ─────────────────────────────────────────────────────
  ➜ Wordlist (ENTER for default) : [.../common.txt]
  ➜ Extensions (ENTER to skip)   : php,txt
  ➜ Threads  [5]        :
  ➜ Rate limit [30]     :
  ➜ Hide status codes   : 404
  ➜ Output file         :
  ➜ Extra flags         :

  ╔══════════════════════════════════════════════════════════════╗
  ║                  Generated Fuzzing Command                   ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  ffuf -u http://10.10.10.10/FUZZ -w .../common.txt          ║
  ║       -e .php,.txt -t 5 -rate 30 -fc 404 -c                 ║
  ╚══════════════════════════════════════════════════════════════╝

  ┌──────────────────────────────────────────────────────────────┐
  │  Run safely (LOW profile):                                   │
  │  nice -n 19 ffuf -u http://10.10.10.10/FUZZ ...             │
  └──────────────────────────────────────────────────────────────┘
```

---

## 📦 Requirements

- Python 3.x (no external libraries — stdlib only)
- [SecLists](https://github.com/danielmiessler/SecLists) installed at `/usr/share/seclists/`
- One or more of the supported fuzzing tools installed

### Install SecLists

```bash
# Debian / Kali / ParrotOS
sudo apt install seclists -y

# or manually
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

### Install Fuzzing Tools

```bash
sudo apt install ffuf feroxbuster wfuzz gobuster dirsearch -y
```

---

## 🚀 Installation & Usage

```bash
git clone https://github.com/rj-karan/RUZZ.git
cd RUZZ
chmod +x fuzzer.py
python3 fuzzer.py
```

No virtual environment or `pip install` needed.

### Run with Low CPU Priority (Recommended)

```bash
nice -n 19 python3 fuzzer.py
```

This keeps your entire machine responsive — not just the fuzzer's output rate.

---

## 🗺️ Interactive Flow

### ⚡ Quick Mode
All inputs on a single screen — no numbered steps, no waiting:
```
➜ Target URL
➜ Tool           (ffuf / feroxbuster / wfuzz / gobuster / dirsearch  or 1-5)
➜ Fuzz type      (dir / param / sub / vhost / api / ext  or 1-6)
➜ Profile        (low / medium / high  or 1-3)
  ─────────────────────────────────────────
➜ Wordlist       (ENTER = smart default for the chosen type)
➜ Extensions
➜ Threads
➜ Rate limit
➜ Hide status codes
➜ Custom header
➜ Output file
➜ Extra flags
  → Command printed instantly ✅
```

### 🗺️ Manual Mode
Step-by-step guided flow — better for beginners or complex setups:
```
Step 0 → Select resource profile (Low / Medium / High)
Step 1 → Select fuzzing tool
Step 2 → Enter target URL / IP with port
Step 3 → Choose fuzzing type
Step 4 → Configure options
           ├── Wordlist (default or custom)
           ├── URL / FUZZ placeholder
           ├── Extensions (php, txt, html…)
           ├── Threads (pre-filled from profile)
           ├── Rate limit (pre-filled from profile)
           ├── Recursion & depth
           ├── Response filters (status / size / words)
           ├── Custom headers
           └── Output file
Step 5 → Copy-paste ready command generated ✅
         + "Run safely" version with nice prefix shown
```

---

## 🗂️ Fuzzing Modes

| # | Mode | Best Tool(s) |
|---|------|-------------|
| 1 | Directory / Subdirectory Fuzzing | ffuf, feroxbuster, gobuster |
| 2 | Parameter Fuzzing | ffuf, wfuzz |
| 3 | Subdomain Fuzzing | ffuf, gobuster (DNS mode) |
| 4 | VHOST Fuzzing | ffuf, gobuster, feroxbuster |
| 5 | API Endpoint Fuzzing | ffuf, feroxbuster |
| 6 | File Extension Fuzzing | ffuf, dirsearch |

---

## 📖 Wordlists Used (SecLists)

| Fuzzing Type | Options |
|--------------|---------|
| Directory | common, raft-medium, raft-large, raft-small, dirbuster-medium, dirbuster-big, combined, big, quickhits |
| Files | raft-medium-files, raft-large-files, raft-small-files, raft-medium-words, raft-large-words |
| Subdomain | subdomains-top1million-5000, subdomains-top1million-20000 |
| Parameter | burp-parameter-names, url-params-top55-apps |
| API | common-api-endpoints-mazen160, graphql, raft-medium-words |
| Extension | web-extensions, web-extensions-big |

You can override any wordlist with a custom path when prompted.

---

## 💡 Example Output Commands

**ffuf — Low-Impact directory fuzzing:**
```bash
nice -n 19 ffuf -u http://192.168.1.10:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt -t 5 -rate 30 -c
```

**ffuf — Full-speed with recursion:**
```bash
ffuf -u http://192.168.1.10:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt -recursion -recursion-depth 2 -t 40 -c
```

**gobuster — Low-Impact DNS subdomain fuzzing:**
```bash
nice -n 19 gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 5 --delay 30ms
```

**wfuzz — Low-Impact parameter fuzzing:**
```bash
nice -n 19 wfuzz --hc 404 --req-delay 0.03 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 5 -u http://target.com/?FUZZ=test
```

**feroxbuster — Medium-impact directory fuzzing:**
```bash
nice -n 10 feroxbuster -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php -x html --depth 2 -t 20 --rate-limit 80 --color
```

---

## 🐳 Docker Usage (Optional Isolation)

If you want to isolate the fuzzer from your host network stack entirely, you can run it in Docker with hard resource caps.

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y \
    ffuf feroxbuster gobuster wfuzz dirsearch \
    python3 seclists --no-install-recommends
WORKDIR /app
COPY . .
ENTRYPOINT ["python3", "fuzzer.py"]
```

```bash
docker build -t ruzz .

# Run with CPU and memory limits
docker run --cpus="0.5" --memory="512m" --network=host -it ruzz
```

> Note: Docker `--cpus` caps CPU independently of `nice`. Use both `--cpus` and `nice -n 19` together for maximum isolation.

---

## 📁 Project Structure

```
RUZZ/
├── fuzzer.py     # Main script — all logic in one file
└── README.md     # This file
```

---

## ⚠️ Disclaimer

This tool is intended **for educational purposes and authorized security testing only** — CTF competitions, HackTheBox, TryHackMe, and penetration testing labs where you have explicit permission.

Do **not** use this tool against systems you do not own or have written permission to test. Unauthorized scanning is illegal.

---

## 🤝 Contributing

Pull requests are welcome! Ideas:

- Add proxy support (`--proxy http://127.0.0.1:8080`)
- Add command history (`~/.ruzz_history`) with `--history` flag
- Add `--no-color` flag for pipe/non-interactive usage
- Add JSON config export so commands can be saved and replayed
- Add profile persistence (remember last used profile)
- Add more tools (e.g. `nikto`, `arjun`)



Made for CTF players, by a CTF player 🚩  
*by **zoro_rj***
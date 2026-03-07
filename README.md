# 🎯 Fuzz Gen — Web CTF Fuzzing Command Generator

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/CTF-Tool-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20ParrotOS-informational?style=for-the-badge"/>
</p>

<p align="center">
  A beginner-friendly, interactive CLI tool that generates copy-paste ready fuzzing commands for the most popular web CTF tools.
  Stop googling flags — just answer the prompts and get your command.
</p>

---

## ✨ Features

- 🛠️ **5 tools supported** — ffuf, feroxbuster, wfuzz, gobuster, dirsearch
- 🔍 **6 fuzzing modes** — Directory, Parameter, Subdomain, VHOST, API Endpoint, File Extension
- 📚 **Auto-suggests SecLists wordlists** based on your chosen fuzzing type
- 🎨 **Color-coded interactive UI** with step-by-step prompts
- 🔁 **Recursion support** with configurable depth (ffuf & feroxbuster)
- 🧵 **Thread count & rate limiting** per tool
- 🔎 **Response filtering** — filter by HTTP status code, response size, or word count
- 📝 **Output file support** in the correct format per tool
- 🪄 **Custom headers** support (e.g. `Cookie`, `Authorization`)
- ⚠️ **Detects if a tool is not installed** in your PATH
- 💡 **Per-tool tips** printed after every command
- 🔄 **Loop mode** — generate multiple commands without restarting

---

## 🖥️ Demo

```
 ██████╗ ██╗   ██╗███████╗███████╗     ██████╗ ███████╗███╗   ██╗
 ██╔══██╗██║   ██║╚══███╔╝╚══███╔╝    ██╔════╝ ██╔════╝████╗  ██║
 ██████╔╝██║   ██║  ███╔╝   ███╔╝     ██║  ███╗█████╗  ██╔██╗ ██║
 ██╔══██╗██║   ██║ ███╔╝   ███╔╝      ██║   ██║██╔══╝  ██║╚██╗██║
 ██║  ██║╚██████╔╝███████╗███████╗    ╚██████╔╝███████╗██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝
          Web CTF Fuzzing Command Generator v2.0

  ╔═══════════════════════════════════════════════════╗
  ║           Generated Fuzzing Command               ║
  ╠═══════════════════════════════════════════════════╣
  ║  ffuf -u http://10.10.10.10/FUZZ                  ║
  ║       -w /.../Web-Content/common.txt              ║
  ║       -e .php,.txt -t 40 -c                       ║
  ╚═══════════════════════════════════════════════════╝
```

---

## 📦 Requirements

- Python 3.x (no external libraries needed — stdlib only)
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
# ffuf
sudo apt install ffuf -y

# feroxbuster
sudo apt install feroxbuster -y

# wfuzz
sudo apt install wfuzz -y

# gobuster
sudo apt install gobuster -y

# dirsearch
sudo apt install dirsearch -y
# or: pip3 install dirsearch
```

---

## 🚀 Installation & Usage

```bash
# Clone the repo
git clone https://github.com/yourusername/fuzz-gen.git
cd fuzz-gen

# Make it executable
chmod +x fuzz_gen.py

# Run it
python3 fuzz_gen.py
```

No virtual environment or `pip install` needed — it uses only Python standard library.

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

| Fuzzing Type | Default Wordlist |
|---|---|
| Directory (small) | `Discovery/Web-Content/common.txt` |
| Directory (large) | `Discovery/Web-Content/directory-list-2.3-medium.txt` |
| Subdomain | `Discovery/DNS/subdomains-top1million-5000.txt` |
| Parameter | `Discovery/Web-Content/burp-parameter-names.txt` |
| VHOST | `Discovery/DNS/subdomains-top1million-5000.txt` |
| API | `Discovery/Web-Content/api/objects.txt` |

You can override any wordlist with a custom path when prompted.

---

## 💡 Example Output Commands

**ffuf — Directory fuzzing with extensions and recursion:**
```bash
ffuf -u http://192.168.1.10:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt -recursion -recursion-depth 2 -t 40 -c
```

**gobuster — DNS subdomain fuzzing:**
```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 40
```

**wfuzz — Parameter fuzzing with status filter:**
```bash
wfuzz --hc 404 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 40 -u http://target.com/?FUZZ=test
```

**feroxbuster — Directory fuzzing with output:**
```bash
feroxbuster -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php -x html --depth 2 -t 40 --color -o results.txt
```

**dirsearch — Directory fuzzing with extensions:**
```bash
dirsearch -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,html,txt,js,json -t 40
```

---

## 🗺️ Interactive Flow

```
Step 1 → Select fuzzing tool
Step 2 → Enter target URL / IP with port
Step 3 → Choose fuzzing type
Step 4 → Configure options
           ├── Wordlist (default or custom)
           ├── URL / FUZZ placeholder
           ├── Extensions (php, txt, html…)
           ├── Threads
           ├── Recursion & depth
           ├── Response filters (status / size / words)
           ├── Custom headers
           ├── Rate limit
           └── Output file
Step 5 → Copy-paste ready command generated ✅
```

---

## 📁 Project Structure

```
fuzz-gen/
├── fuzz_gen.py       # Main script — all logic in one file
└── README.md         # This file
```

---

## ⚠️ Disclaimer

This tool is intended **for educational purposes and authorized security testing only** — such as CTF competitions, HackTheBox, TryHackMe, and penetration testing labs where you have explicit permission.

Do **not** use this tool against systems you do not own or have written permission to test. Unauthorized scanning is illegal.

---

## 🤝 Contributing

Pull requests are welcome! Ideas for contributions:

- Add support for more tools (e.g. `feroxbuster` spray mode, `nikto`, `arjun`)
- Add proxy support (`--proxy http://127.0.0.1:8080`)
- Add a `--no-color` flag for non-interactive / pipe usage
- Add JSON config file export so commands can be saved and replayed

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">Made for CTF players, by a CTF player 🚩</p>
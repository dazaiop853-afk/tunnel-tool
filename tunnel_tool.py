#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║                    TunnelTool v1.1.0                             ║
║       Multi-Hop Reverse SSH Tunnel Manager                       ║
║                                                                  ║
║  USA PC:      curl -sL <CDN_URL> | python3 -                    ║
║  Field Unit:  curl -sL <CDN_URL> | python3 - --field-unit       ║
║  Unfiltered:  curl -sL <CDN_URL> | python3 - -u                 ║
╚══════════════════════════════════════════════════════════════════╝

Architecture:
  Node A (USA PC) --> Node B (Germany Relay) <-- Node C (Iran Field Unit)
                                                      |
                                                      v
                                                 Node D (Iran Server)

v1.1.0:
  - ZERO external deps on field unit: PTY-based password automation (stdlib)
  - Relay-as-proxy: installs any missing tools THROUGH the SSH tunnel
  - Aggressive timeouts for GFW-filtered environments
"""

__version__ = "1.1.0"
__source_url__ = "https://raw.githubusercontent.com/dazaiop853-afk/tunneltool/main/tunnel_tool.py"
__cdn_url__ = "https://cdn.jsdelivr.net/gh/dazaiop853-afk/tunneltool/tunnel_tool.py"


import sys, os, signal, subprocess, shutil, time, json, re, atexit
import argparse, getpass, socket, threading, select, pty, errno
from pathlib import Path
from typing import Optional, List, Tuple

TOOL_NAME = "tunneltool"
CONFIG_DIR = Path.home() / f".{TOOL_NAME}"
CONFIG_FILE = CONFIG_DIR / "config.json"
KNOWN_HOSTS_FILE = CONFIG_DIR / "known_hosts"
KEY_NAME = f"id_rsa_{TOOL_NAME}"
LOCAL_KEY_PATH = CONFIG_DIR / KEY_NAME
LOG_FILE = CONFIG_DIR / "tunnel.log"

REVERSE_TUNNEL_PORT = 2222
SOCKS_PROXY_PORT = 1080
BOOTSTRAP_SOCKS_PORT = 19876
SSH_ALIVE_INTERVAL = 15
SSH_ALIVE_COUNT_MAX = 3
CONNECTION_TIMEOUT = 20
GFW_CONNECTION_TIMEOUT = 45
DEFAULT_SSH_USER = "root"

CHILD_PROCESSES: List[subprocess.Popen] = []
TEMP_FILES: List[str] = []

class C:
    RESET="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; GREEN="\033[92m"
    YELLOW="\033[93m"; BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"; DIM="\033[2m"

def log(msg, level="INFO"):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {msg}\n")
    except: pass

def print_banner():
    print(f"\n{C.CYAN}{C.BOLD}"
          f"{'='*62}\n"
          f"   TunnelTool v{__version__} - Multi-Hop Reverse SSH Tunnel Manager\n"
          f"{'='*62}{C.RESET}\n")

def info(msg):  print(f"  {C.GREEN}ok{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}!!{C.RESET} {msg}")
def error(msg): print(f"  {C.RED}xx{C.RESET} {msg}")
def step(msg):  print(f"\n{C.BLUE}{C.BOLD}>> {msg}{C.RESET}")
def dim(msg):   print(f"  {C.DIM}{msg}{C.RESET}")

def ask_yes_no(prompt, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        try: resp = input(f"  {C.YELLOW}?{C.RESET} {prompt}{suffix}").strip().lower()
        except EOFError: return default
        if resp == "": return default
        if resp in ("y","yes"): return True
        if resp in ("n","no"): return False

def ask_input(prompt, secret=False):
    try:
        if secret: return getpass.getpass(f"  {C.YELLOW}?{C.RESET} {prompt}: ")
        return input(f"  {C.YELLOW}?{C.RESET} {prompt}: ").strip()
    except EOFError: return ""

def detect_os():
    import platform
    return "macos" if platform.system().lower() == "darwin" else "linux"

def run_cmd(cmd, timeout=60, capture=True, suppress_errors=False, env=None):
    run_env = os.environ.copy()
    if env: run_env.update(env)
    try:
        proc = subprocess.Popen(cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            text=True, env=run_env)
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(); return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        if not suppress_errors: log(f"run_cmd error: {e}", "ERROR")
        return -3, "", str(e)

def spawn_background(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    CHILD_PROCESSES.append(proc)
    return proc

# ---- PTY-BASED PASSWORD AUTOMATION (replaces sshpass) ----

def pty_run(cmd, password, timeout=30):
    """Run SSH cmd feeding password via PTY. Stdlib only. Returns (rc, output, hint)."""
    chunks = []
    pw_sent = False
    master_fd = None
    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                                close_fds=True, text=False)
        CHILD_PROCESSES.append(proc)
        os.close(slave_fd)
        deadline = time.time() + timeout
        while time.time() < deadline:
            rem = deadline - time.time()
            if rem <= 0: break
            try: ready, _, _ = select.select([master_fd], [], [], min(rem, 0.5))
            except (ValueError, OSError): break
            if ready:
                try: data = os.read(master_fd, 4096)
                except OSError as e:
                    if e.errno == errno.EIO: break
                    raise
                if not data: break
                decoded = data.decode("utf-8", errors="replace")
                chunks.append(decoded)
                if not pw_sent and re.search(r'[Pp]ass(?:word|phrase)[^:]*:', decoded):
                    time.sleep(0.1)
                    os.write(master_fd, (password + "\n").encode())
                    pw_sent = True
            if proc.poll() is not None:
                try:
                    while True:
                        r, _, _ = select.select([master_fd], [], [], 0.2)
                        if not r: break
                        d = os.read(master_fd, 4096)
                        if not d: break
                        chunks.append(d.decode("utf-8", errors="replace"))
                except OSError: pass
                break
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except: proc.kill(); proc.wait()
        full = "".join(chunks)
        clean = "\n".join(l for l in full.split("\n")
                          if password not in l and not re.search(r'[Pp]ass(?:word|phrase)[^:]*:', l)).strip()
        hint = ""
        for pat, msg in [("REMOTE HOST IDENTIFICATION HAS CHANGED","REMOTE HOST IDENTIFICATION HAS CHANGED"),
                         ("Permission denied","Permission denied"),("Connection refused","Connection refused"),
                         ("onnection timed out","Connection timed out"),
                         ("Host key verification failed","Host key verification failed"),
                         ("No route to host","No route to host")]:
            if pat in full: hint = msg; break
        return (proc.returncode if proc.returncode is not None else -1), clean, hint
    except Exception as e:
        log(f"pty_run error: {e}", "ERROR"); return -3, "", str(e)
    finally:
        if master_fd is not None:
            try: os.close(master_fd)
            except: pass

def has_sshpass():
    return shutil.which("sshpass") is not None

def password_ssh(cmd_args, password, timeout=30):
    """Run SSH with password. Prefers sshpass, falls back to PTY."""
    if has_sshpass():
        return run_cmd(["sshpass", "-p", password] + cmd_args, timeout=timeout)
    return pty_run(cmd_args, password, timeout=timeout)

# ---- SIGNAL HANDLING & CLEANUP ----

def cleanup():
    for proc in CHILD_PROCESSES:
        try: proc.terminate(); proc.wait(timeout=5)
        except:
            try: proc.kill()
            except: pass
    for f in TEMP_FILES:
        try: os.unlink(f)
        except: pass

def signal_handler(signum, frame):
    signame = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
    print(f"\n\n  {C.YELLOW}!!{C.RESET} Caught {signame}. Cleaning up...")
    cleanup()
    print(f"  {C.GREEN}ok{C.RESET} All tunnels and child processes terminated.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup)

# ---- FRIENDLY ERRORS ----

def _friendly_err(stderr):
    s = stderr.lower()
    if "connection refused" in s: return "Connection refused - SSH may not be running"
    if "timed out" in s: return "Connection timed out - host unreachable or firewalled"
    if "permission denied" in s: return "Permission denied - wrong password or key"
    if "no route to host" in s: return "No route to host - network unreachable"
    if "host key verification" in s: return "Host key mismatch - will auto-fix"
    if "name or service not known" in s: return "Hostname could not be resolved"
    return stderr.strip().split("\n")[-1] if stderr.strip() else "Unknown error"

# ---- SSH OPTION BUILDERS ----

def base_ssh_opts():
    return ["-o","StrictHostKeyChecking=accept-new",
            "-o",f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
            "-o",f"ServerAliveInterval={SSH_ALIVE_INTERVAL}",
            "-o",f"ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}",
            "-o","ConnectTimeout=20","-o","LogLevel=ERROR",
            "-i",str(LOCAL_KEY_PATH)]

def base_ssh_opts_no_key():
    return ["-o","StrictHostKeyChecking=accept-new",
            "-o",f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
            "-o",f"ServerAliveInterval={SSH_ALIVE_INTERVAL}",
            "-o",f"ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}",
            "-o","ConnectTimeout=20","-o","LogLevel=ERROR"]

# ---- KNOWN HOSTS ----

def remove_host_key(host, port=22):
    if not KNOWN_HOSTS_FILE.exists(): return
    target = f"[{host}]:{port}" if port != 22 else host
    run_cmd(["ssh-keygen","-f",str(KNOWN_HOSTS_FILE),"-R",target], timeout=10, suppress_errors=True)

# ---- STATE / CONFIG ----

def load_config():
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except: return {}
    return {}

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def wipe_config():
    step("Wiping configuration")
    for f in [CONFIG_FILE, KNOWN_HOSTS_FILE, LOG_FILE]:
        if f.exists(): f.unlink(); info(f"{f.name} removed")
    if LOCAL_KEY_PATH.exists():
        if ask_yes_no("SSH keys exist. Remove them too?", default=False):
            LOCAL_KEY_PATH.unlink()
            Path(str(LOCAL_KEY_PATH)+".pub").unlink(missing_ok=True)
            info("SSH keys removed")
        else: info("SSH keys preserved")
    info("Wipe complete")

def fresh_start_prompt():
    step("State Management")
    if CONFIG_DIR.exists() and any(CONFIG_DIR.iterdir()):
        if ask_yes_no("Wipe all existing configs and start fresh?", default=False):
            wipe_config()

# ---- SSH KEY MANAGEMENT (LOCAL) ----

def ensure_local_keys():
    step("Key Management (Local)")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    pub = Path(str(LOCAL_KEY_PATH)+".pub")
    if LOCAL_KEY_PATH.exists() and pub.exists():
        info(f"Keys exist: {LOCAL_KEY_PATH.name}"); return LOCAL_KEY_PATH
    info("Generating new SSH key pair...")
    rc, _, stderr = run_cmd(["ssh-keygen","-t","rsa","-b","4096",
                              "-f",str(LOCAL_KEY_PATH),"-N","",
                              "-C",f"{TOOL_NAME}@{socket.gethostname()}"], timeout=30)
    if rc != 0: error(f"Key generation failed: {stderr.strip()}"); sys.exit(1)
    os.chmod(LOCAL_KEY_PATH, 0o600)
    info(f"Key generated: {LOCAL_KEY_PATH.name}")
    return LOCAL_KEY_PATH

def get_pub_key():
    return Path(str(LOCAL_KEY_PATH)+".pub").read_text().strip()

# ---- CONNECTION TESTING ----

def test_key_auth(host, user, port=22, timeout=CONNECTION_TIMEOUT):
    cmd = ["ssh",*base_ssh_opts(),"-o","BatchMode=yes",
           "-o",f"ConnectTimeout={timeout}","-p",str(port),
           f"{user}@{host}","echo OK"]
    rc, stdout, _ = run_cmd(cmd, timeout=timeout+10)
    return rc == 0 and "OK" in stdout

def test_password_auth(host, user, password, port=22, timeout=CONNECTION_TIMEOUT):
    cmd = ["ssh",*base_ssh_opts_no_key(),"-o",f"ConnectTimeout={timeout}",
           "-o","PubkeyAuthentication=no","-p",str(port),
           f"{user}@{host}","echo OK"]
    rc, stdout, hint = password_ssh(cmd, password, timeout=timeout+15)
    if rc == 0 and "OK" in stdout: return True
    if "IDENTIFICATION HAS CHANGED" in hint or "verification" in hint.lower():
        warn("Remote host key changed - auto-fixing...")
        remove_host_key(host, port)
        rc, stdout, _ = password_ssh(cmd, password, timeout=timeout+15)
        return rc == 0 and "OK" in stdout
    return False

def copy_key_to_host(host, user, password, port=22, timeout=CONNECTION_TIMEOUT):
    step(f"Copying key to {user}@{host}:{port}")
    pub_content = get_pub_key()
    # Method 1: sshpass + ssh-copy-id
    if has_sshpass():
        cmd = ["sshpass","-p",password,"ssh-copy-id","-i",str(LOCAL_KEY_PATH)+".pub",
               "-o","StrictHostKeyChecking=accept-new",
               "-o",f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
               "-o",f"ConnectTimeout={timeout}","-p",str(port),f"{user}@{host}"]
        rc, _, stderr = run_cmd(cmd, timeout=timeout+15)
        if "IDENTIFICATION HAS CHANGED" in stderr:
            remove_host_key(host, port)
            rc, _, stderr = run_cmd(cmd, timeout=timeout+15)
        if rc == 0: info(f"Key copied to {host}"); return True
        warn(f"ssh-copy-id failed, trying manual method...")
    # Method 2: PTY-based manual injection
    escaped = pub_content.replace('"', '\\"')
    inject = (f'mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
              f'grep -qF "{escaped}" ~/.ssh/authorized_keys 2>/dev/null || '
              f'echo "{escaped}" >> ~/.ssh/authorized_keys && '
              f'chmod 600 ~/.ssh/authorized_keys && echo KEYDONE')
    ssh_cmd = ["ssh",*base_ssh_opts_no_key(),"-o",f"ConnectTimeout={timeout}",
               "-o","PubkeyAuthentication=no","-p",str(port),f"{user}@{host}",inject]
    rc, stdout, hint = password_ssh(ssh_cmd, password, timeout=timeout+15)
    if "IDENTIFICATION HAS CHANGED" in hint:
        remove_host_key(host, port)
        rc, stdout, hint = password_ssh(ssh_cmd, password, timeout=timeout+15)
    if rc == 0 and "KEYDONE" in stdout:
        info(f"Key copied to {host}"); return True
    error(f"Key copy failed: {_friendly_err(hint or 'unknown')}"); return False

# ---- RELAY-AS-PROXY: BOOTSTRAP TUNNEL FOR DEPENDENCY INSTALLS ----

class RelayProxy:
    """Temp SOCKS5 proxy through relay. Routes brew/pip/curl through tunnel."""
    def __init__(self):
        self.proc = None
        self.port = BOOTSTRAP_SOCKS_PORT
        self.active = False

    def start(self, relay_host, relay_user, relay_port=22, password=""):
        step("Opening temporary proxy through relay for downloads")
        ssh_cmd = ["ssh","-N","-D",f"127.0.0.1:{self.port}",
                   "-o","ExitOnForwardFailure=yes",
                   "-o","StrictHostKeyChecking=accept-new",
                   "-o",f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
                   "-o",f"ServerAliveInterval={SSH_ALIVE_INTERVAL}",
                   "-o",f"ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}",
                   "-o",f"ConnectTimeout={GFW_CONNECTION_TIMEOUT}",
                   "-o","LogLevel=ERROR","-p",str(relay_port)]

        if LOCAL_KEY_PATH.exists() and test_key_auth(relay_host, relay_user, relay_port, timeout=GFW_CONNECTION_TIMEOUT):
            ssh_cmd += ["-i",str(LOCAL_KEY_PATH),f"{relay_user}@{relay_host}"]
            self.proc = spawn_background(ssh_cmd)
        elif password:
            ssh_cmd += ["-o","PubkeyAuthentication=no",f"{relay_user}@{relay_host}"]
            if has_sshpass():
                self.proc = spawn_background(["sshpass","-p",password]+ssh_cmd)
            else:
                info("Starting proxy via PTY (no sshpass)...")
                self.proc = self._start_pty_proxy(ssh_cmd, password)
        else:
            error("No key or password for relay proxy"); return False

        for i in range(10):
            time.sleep(1)
            if self.proc and self.proc.poll() is not None:
                error("Proxy process died immediately"); return False
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=1)
                s.close()
                self.active = True
                info(f"Relay proxy active on 127.0.0.1:{self.port}")
                return True
            except (ConnectionRefusedError, OSError): continue

        warn("Proxy may not be ready yet, continuing anyway...")
        self.active = True
        return True

    def _start_pty_proxy(self, ssh_cmd, password):
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(ssh_cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                                close_fds=True, text=False)
        CHILD_PROCESSES.append(proc)
        os.close(slave_fd)
        def _feed():
            sent = False
            deadline = time.time() + GFW_CONNECTION_TIMEOUT
            while time.time() < deadline and proc.poll() is None:
                try: r, _, _ = select.select([master_fd], [], [], 0.5)
                except (ValueError, OSError): break
                if r:
                    try: data = os.read(master_fd, 4096)
                    except OSError: break
                    if not data: break
                    if not sent and re.search(r'[Pp]ass(?:word|phrase)[^:]*:', data.decode("utf-8","replace")):
                        time.sleep(0.1)
                        os.write(master_fd, (password + "\n").encode())
                        sent = True
            # Keep draining to prevent buffer deadlock
            while proc.poll() is None:
                try:
                    r, _, _ = select.select([master_fd], [], [], 1)
                    if r: os.read(master_fd, 4096)
                except (ValueError, OSError): break
            try: os.close(master_fd)
            except: pass
        threading.Thread(target=_feed, daemon=True).start()
        return proc

    def proxy_env(self):
        p = f"socks5h://127.0.0.1:{self.port}"
        return {"http_proxy":p,"https_proxy":p,"HTTP_PROXY":p,
                "HTTPS_PROXY":p,"all_proxy":p,"ALL_PROXY":p}

    def stop(self):
        if self.proc:
            try: self.proc.terminate(); self.proc.wait(timeout=5)
            except:
                try: self.proc.kill()
                except: pass
            if self.proc in CHILD_PROCESSES: CHILD_PROCESSES.remove(self.proc)
            self.proc = None; self.active = False
            dim("Relay proxy stopped")

# ---- DEPENDENCY BOOTSTRAP (routes through relay proxy if on filtered network) ----

def bootstrap_dependencies(proxy=None):
    step("Checking dependencies")
    for tool in ["ssh","ssh-keygen"]:
        if shutil.which(tool): dim(f"{tool}: found")
        else: error(f"'{tool}' not found. Install OpenSSH."); sys.exit(1)
    if shutil.which("ssh-copy-id"): dim("ssh-copy-id: found")
    else: warn("ssh-copy-id: not found (will use manual key injection)")
    if has_sshpass():
        dim("sshpass: found")
    else:
        dim("sshpass: not found (using built-in PTY password automation)")
        if proxy and proxy.active:
            if ask_yes_no("Install sshpass through relay tunnel? (optional, improves reliability)"):
                _install_sshpass_via_proxy(proxy)
    info("Dependencies satisfied")

def _install_sshpass_via_proxy(proxy):
    step("Installing sshpass via relay tunnel")
    os_type = detect_os()
    env = proxy.proxy_env()
    if os_type == "macos":
        if not shutil.which("brew"):
            warn("Homebrew not found, skipping"); return
        info("brew install sshpass (via relay proxy)...")
        rc, _, _ = run_cmd(["brew","install","hudochenkov/sshpass/sshpass"], timeout=180, env=env)
        if rc == 0 and has_sshpass(): info("sshpass installed!"); return
        warn("brew failed, trying source build...")
        _build_sshpass_from_source(proxy)
    else:
        info("apt-get install sshpass (via relay proxy)...")
        rc, _, _ = run_cmd(["sudo","apt-get","install","-y","sshpass"], timeout=120, env=env)
        if rc == 0 and has_sshpass(): info("sshpass installed!"); return
        warn("apt failed, trying source build...")
        _build_sshpass_from_source(proxy)

def _build_sshpass_from_source(proxy):
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="tunneltool_")
    TEMP_FILES.append(tmpdir)
    tarball = os.path.join(tmpdir, "sshpass.tar.gz")
    rc, _, _ = run_cmd(["curl","-sL","--proxy",f"socks5h://127.0.0.1:{proxy.port}",
                         "-o",tarball,
                         "https://sourceforge.net/projects/sshpass/files/latest/download"],
                        timeout=60)
    if rc != 0: warn("Could not download sshpass source"); return
    rc, _, _ = run_cmd(["tar","xzf",tarball,"-C",tmpdir], timeout=30)
    if rc != 0: warn("Could not extract sshpass"); return
    dirs = [d for d in os.listdir(tmpdir) if d.startswith("sshpass") and os.path.isdir(os.path.join(tmpdir,d))]
    if not dirs: warn("sshpass source dir not found"); return
    srcdir = os.path.join(tmpdir, dirs[0])
    prefix = os.path.join(str(Path.home()), ".local")
    for cmd in [["./configure",f"--prefix={prefix}"],["make"],["make","install"]]:
        rc, _, _ = run_cmd(cmd, timeout=120)
        if rc != 0: warn(f"sshpass build step failed: {cmd[0]}"); return
    os.environ["PATH"] = os.path.join(prefix,"bin") + ":" + os.environ["PATH"]
    if has_sshpass(): info("sshpass built from source!")
    else: warn("sshpass built but not on PATH")

# ---- SELF-UPDATE (routes through relay proxy on filtered networks) ----

def check_for_updates(proxy=None):
    step("Checking for updates")
    try:
        if proxy and proxy.active:
            rc, stdout, _ = run_cmd(["curl","-sL","--proxy",f"socks5h://127.0.0.1:{proxy.port}",
                                      "--max-time","10",__source_url__], timeout=15)
            if rc != 0: dim("Update check failed via proxy"); return
            remote_source = stdout
        else:
            import urllib.request
            req = urllib.request.Request(__source_url__, method='GET')
            req.add_header('User-Agent', f'TunnelTool/{__version__}')
            with urllib.request.urlopen(req, timeout=8) as resp:
                remote_source = resp.read().decode('utf-8')
        match = re.search(r'__version__\s*=\s*"([^"]+)"', remote_source)
        if match:
            rv = match.group(1)
            if rv != __version__:
                warn(f"New version: v{rv} (current: v{__version__})")
                if ask_yes_no("Re-run curl command to update?"):
                    info("Please re-run the curl | python3 command"); sys.exit(0)
                info("Continuing with current version")
            else: info(f"Up to date (v{__version__})")
        else: dim("Could not parse remote version")
    except Exception as e:
        dim(f"Update check skipped: {e}")

# ---- INTERACTIVE HOST SETUP ----

def get_host_credentials(node_name, config_key, cfg, timeout=CONNECTION_TIMEOUT):
    step(f"Setting up {node_name}")
    saved = cfg.get(config_key)
    if saved:
        ip = saved.get("ip",""); user = saved.get("user",DEFAULT_SSH_USER)
        info(f"Saved config: {user}@{ip}")
        if test_key_auth(ip, user, timeout=timeout):
            info(f"Key auth working for {ip}"); return ip, user, ""
        warn(f"Key auth failed for {ip}. Need password or new IP.")
        if not ask_yes_no(f"Try {ip} with password?", default=True):
            del cfg[config_key]; save_config(cfg)
            return _prompt_new_host(node_name, config_key, cfg, timeout)
        pw = ask_input(f"Password for {user}@{ip}", secret=True)
        if not ask_yes_no("Password entered correctly?", default=True):
            pw = ask_input("Password (re-enter)", secret=True)
        if test_password_auth(ip, user, pw, timeout=timeout):
            info(f"{ip} is healthy"); return ip, user, pw
        error(f"Cannot reach {node_name} at {ip}")
        del cfg[config_key]; save_config(cfg)
        return _prompt_new_host(node_name, config_key, cfg, timeout)
    return _prompt_new_host(node_name, config_key, cfg, timeout)

def _prompt_new_host(node_name, config_key, cfg, timeout):
    for attempt in range(3):
        ip = ask_input(f"IP address for {node_name}")
        user = ask_input(f"SSH user (default: {DEFAULT_SSH_USER})") or DEFAULT_SSH_USER
        pw = ask_input(f"Password for {user}@{ip}", secret=True)
        if not ask_yes_no("Password entered correctly?", default=True):
            pw = ask_input("Password (re-enter)", secret=True)
        dim(f"Testing connection to {user}@{ip}...")
        if test_key_auth(ip, user, timeout=timeout):
            info(f"{ip} healthy (key auth)")
            cfg[config_key] = {"ip":ip,"user":user}; save_config(cfg)
            return ip, user, pw
        if test_password_auth(ip, user, pw, timeout=timeout):
            info(f"{ip} healthy")
            cfg[config_key] = {"ip":ip,"user":user}; save_config(cfg)
            return ip, user, pw
        error(f"IP unhealthy - cannot reach {ip}")
        if attempt < 2: warn("Please enter a new IP")
    error(f"Could not connect to {node_name} after 3 attempts"); sys.exit(1)

# ---- REMOTE EXEC HELPERS ----

def remote_exec(host, user, cmd_str, port=22, timeout=30, password=""):
    if password and not test_key_auth(host, user, port, timeout=10):
        ssh_cmd = ["ssh",*base_ssh_opts_no_key(),"-o","PubkeyAuthentication=no",
                   "-p",str(port),f"{user}@{host}",cmd_str]
        return password_ssh(ssh_cmd, password, timeout=timeout)
    ssh_cmd = ["ssh",*base_ssh_opts(),"-p",str(port),f"{user}@{host}",cmd_str]
    return run_cmd(ssh_cmd, timeout=timeout)

def ensure_remote_key(host, user, port=22, password=""):
    step(f"Ensuring SSH key on {user}@{host}")
    check = f'test -f ~/.ssh/{KEY_NAME} && cat ~/.ssh/{KEY_NAME}.pub || echo "NOKEY"'
    rc, stdout, _ = remote_exec(host, user, check, port, password=password)
    if rc == 0 and "NOKEY" not in stdout and stdout.strip():
        info(f"Key exists on {host}"); return stdout.strip()
    info(f"Generating key on {host}...")
    gen = (f'ssh-keygen -t rsa -b 4096 -f ~/.ssh/{KEY_NAME} -N "" '
           f'-C "{TOOL_NAME}@{host}" 2>/dev/null && cat ~/.ssh/{KEY_NAME}.pub')
    rc, stdout, stderr = remote_exec(host, user, gen, port, timeout=30, password=password)
    if rc == 0 and stdout.strip(): info(f"Key generated on {host}"); return stdout.strip()
    error(f"Key gen failed: {stderr.strip()}"); return None

# ---- PORT MANAGEMENT ----

def kill_port_holder(host, user, port, ssh_port=22, password=""):
    step(f"Checking port {port} on {host}")
    cmd = f"lsof -ti :{port} 2>/dev/null || ss -tlnp 2>/dev/null | grep :{port} | grep -oP '(?<=pid=)\\d+'"
    rc, stdout, _ = remote_exec(host, user, cmd, ssh_port, password=password)
    if rc == 0 and stdout.strip():
        pids = [p.strip() for p in stdout.strip().split("\n") if p.strip().isdigit()]
        if pids:
            warn(f"Port {port} busy (PID: {', '.join(pids)}). Killing...")
            remote_exec(host, user, f"kill -9 {' '.join(pids)} 2>/dev/null", ssh_port, password=password)
            time.sleep(1); info(f"Port {port} freed"); return True
    info(f"Port {port} available"); return True

# ---- TUNNEL ESTABLISHMENT ----

def establish_reverse_tunnel(relay_host, relay_user, relay_port=22):
    step(f"Establishing reverse tunnel via {relay_host}")
    cmd = ["ssh",*base_ssh_opts(),"-N",
           "-R",f"{REVERSE_TUNNEL_PORT}:localhost:22",
           "-o","ExitOnForwardFailure=yes",
           "-p",str(relay_port),f"{relay_user}@{relay_host}"]
    info(f"Tunnel: {relay_host}:{REVERSE_TUNNEL_PORT} <- localhost:22")
    proc = spawn_background(cmd)
    time.sleep(4)
    if proc.poll() is not None:
        _, stderr = proc.communicate()
        error(f"Tunnel failed: {_friendly_err(stderr)}"); return None
    info("Reverse tunnel established!"); return proc

def monitor_tunnel(proc, name):
    def _mon():
        proc.wait()
        if proc.returncode and proc.returncode != 0:
            error(f"Tunnel '{name}' died (code {proc.returncode})")
    threading.Thread(target=_mon, daemon=True).start()

# ---- SUCCESS BANNER & CONFIG GEN ----

def print_success_banner(relay_ip, relay_user, field_user,
                         iran_ip="", iran_user="", unfiltered=False):
    print(f"\n{C.GREEN}{C.BOLD}{'='*62}")
    print(f"   SETUP COMPLETE")
    print(f"{'='*62}{C.RESET}")
    print(f"\n{C.CYAN}{C.BOLD}  GOAL 1: Connect to Field Unit via Relay{C.RESET}")
    print(f"\n  {C.YELLOW}ssh -J {relay_user}@{relay_ip} \\")
    print(f"      -i {LOCAL_KEY_PATH} \\")
    print(f"      -o UserKnownHostsFile={KNOWN_HOSTS_FILE} \\")
    print(f"      -p {REVERSE_TUNNEL_PORT} {field_user}@localhost{C.RESET}")
    if iran_ip:
        print(f"\n{C.CYAN}{C.BOLD}  GOAL 2: Connect to Iran Server via Field Unit{C.RESET}")
        print(f"\n  {C.YELLOW}ssh -J {relay_user}@{relay_ip},{field_user}@localhost:{REVERSE_TUNNEL_PORT} \\")
        print(f"      -i {LOCAL_KEY_PATH} \\")
        print(f"      -o UserKnownHostsFile={KNOWN_HOSTS_FILE} \\")
        print(f"      {iran_user}@{iran_ip}{C.RESET}")
    if unfiltered:
        print(f"\n{C.MAGENTA}{C.BOLD}  UNFILTERED MODE (SOCKS5 on 127.0.0.1:{SOCKS_PROXY_PORT}){C.RESET}")
        print(f"\n  {C.YELLOW}export all_proxy=socks5h://127.0.0.1:{SOCKS_PROXY_PORT}")
        print(f"  curl ifconfig.me{C.RESET}")
    print(f"\n{C.GREEN}{C.BOLD}{'='*62}{C.RESET}\n")

def generate_ssh_config(relay_ip, relay_user, field_user, iran_ip="", iran_user=""):
    step("SSH Config Snippet (optional)")
    snippet = f"""
# --- TunnelTool Generated Config ---
Host relay
    HostName {relay_ip}
    User {relay_user}
    IdentityFile {LOCAL_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval {SSH_ALIVE_INTERVAL}
    ServerAliveCountMax {SSH_ALIVE_COUNT_MAX}

Host field-unit
    HostName localhost
    Port {REVERSE_TUNNEL_PORT}
    User {field_user}
    ProxyJump relay
    IdentityFile {LOCAL_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval {SSH_ALIVE_INTERVAL}
    ServerAliveCountMax {SSH_ALIVE_COUNT_MAX}
"""
    if iran_ip:
        snippet += f"""
Host iran-server
    HostName {iran_ip}
    User {iran_user}
    ProxyJump field-unit
    IdentityFile {LOCAL_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval {SSH_ALIVE_INTERVAL}
    ServerAliveCountMax {SSH_ALIVE_COUNT_MAX}
"""
    snippet += "# --- End TunnelTool Config ---\n"
    if ask_yes_no("Add aliases to ~/.ssh/config? (ssh field-unit / ssh iran-server)"):
        ssh_cfg = Path.home() / ".ssh" / "config"
        ssh_cfg.parent.mkdir(parents=True, exist_ok=True)
        if ssh_cfg.exists():
            content = ssh_cfg.read_text()
            content = re.sub(r'# --- TunnelTool Generated Config ---.*?# --- End TunnelTool Config ---\n',
                             '', content, flags=re.DOTALL)
            ssh_cfg.write_text(content + snippet)
        else: ssh_cfg.write_text(snippet)
        os.chmod(ssh_cfg, 0o600)
        info("SSH config updated:"); print(f"    {C.YELLOW}ssh field-unit{C.RESET}")
        if iran_ip: print(f"    {C.YELLOW}ssh iran-server{C.RESET}")
    else:
        info("Snippet (copy manually):"); print(f"{C.DIM}{snippet}{C.RESET}")

# ---- MAIN ORCHESTRATOR ----

def main():
    parser = argparse.ArgumentParser(description="TunnelTool - Multi-Hop Reverse SSH Tunnel Manager")
    parser.add_argument("-u","--unfiltered", action="store_true", help="Enable SOCKS5 proxy")
    parser.add_argument("--field-unit", action="store_true", help="Field Unit mode (initiate reverse tunnel)")
    parser.add_argument("--version", action="version", version=f"TunnelTool v{__version__}")
    args = parser.parse_args()

    print_banner()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KNOWN_HOSTS_FILE.touch(exist_ok=True)

    # ================================================================
    # FIELD UNIT MODE (Node C - Iran)
    # ================================================================
    if args.field_unit:
        step("=== FIELD UNIT MODE ===")
        info("This machine will create a reverse tunnel to the Relay.")
        info("All downloads will route THROUGH the relay (bypasses filtering).\n")

        # Phase 0: Minimal offline checks
        for tool in ["ssh","ssh-keygen"]:
            if not shutil.which(tool): error(f"'{tool}' missing"); sys.exit(1)
            dim(f"{tool}: found")

        # Phase 1: Fresh start
        fresh_start_prompt()

        # Phase 2: Local keys (offline)
        ensure_local_keys()
        cfg = load_config()

        # Phase 3: Get relay creds (SSH-only, works through GFW)
        relay_ip, relay_user, relay_pw = get_host_credentials(
            "Germany Relay (Node B)", "relay", cfg, timeout=GFW_CONNECTION_TIMEOUT)

        # Phase 4: Copy our key to relay
        if relay_pw and not test_key_auth(relay_ip, relay_user, timeout=GFW_CONNECTION_TIMEOUT):
            copy_key_to_host(relay_ip, relay_user, relay_pw, timeout=GFW_CONNECTION_TIMEOUT)

        # Phase 5: Open temp SOCKS proxy through relay for downloads
        proxy = RelayProxy()
        proxy_ok = proxy.start(relay_ip, relay_user, password=relay_pw)

        # Phase 6: Update check (through proxy)
        if proxy_ok: check_for_updates(proxy)

        # Phase 7: Install optional deps (through proxy)
        if proxy_ok: bootstrap_dependencies(proxy)

        # Phase 8: Tear down temp proxy
        proxy.stop()

        # Phase 9: Kill stale port holder
        kill_port_holder(relay_ip, relay_user, REVERSE_TUNNEL_PORT, password=relay_pw)

        # Phase 10: Establish reverse tunnel
        tunnel_proc = establish_reverse_tunnel(relay_ip, relay_user)
        if not tunnel_proc:
            error("Failed to establish reverse tunnel."); sys.exit(1)
        monitor_tunnel(tunnel_proc, "reverse-tunnel")

        print(f"\n{C.GREEN}{C.BOLD}{'='*62}")
        print(f"   REVERSE TUNNEL ACTIVE")
        print(f"   Relay {relay_ip}:{REVERSE_TUNNEL_PORT} -> This Machine:22")
        print(f"   Press Ctrl+C to disconnect.")
        print(f"{'='*62}{C.RESET}\n")

        # Auto-reconnect loop
        try:
            while True:
                if tunnel_proc.poll() is not None:
                    warn("Tunnel dropped! Reconnecting in 5s...")
                    time.sleep(5)
                    kill_port_holder(relay_ip, relay_user, REVERSE_TUNNEL_PORT, password=relay_pw)
                    tunnel_proc = establish_reverse_tunnel(relay_ip, relay_user)
                    if tunnel_proc: monitor_tunnel(tunnel_proc, "reverse-tunnel")
                    else: error("Reconnect failed. Retrying in 30s..."); time.sleep(30)
                time.sleep(5)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)

    # ================================================================
    # CLIENT MODE (Node A - USA PC)
    # ================================================================
    else:
        step("=== CLIENT MODE (USA PC) ===")

        # Phase 0: Update & deps (direct internet)
        check_for_updates()
        bootstrap_dependencies()

        # Phase 1: Fresh start
        fresh_start_prompt()

        # Phase 2: Keys
        ensure_local_keys()
        cfg = load_config()

        # Phase 3: Setup Relay (Node B)
        relay_ip, relay_user, relay_pw = get_host_credentials(
            "Germany Relay Server (Node B)", "relay", cfg)
        if relay_pw and not test_key_auth(relay_ip, relay_user):
            copy_key_to_host(relay_ip, relay_user, relay_pw)
        if not test_key_auth(relay_ip, relay_user):
            error("Key auth to relay failed."); sys.exit(1)
        info("Relay key auth confirmed")

        # Phase 4: Check reverse tunnel
        step("Checking if Field Unit reverse tunnel is active")
        rc, stdout, _ = remote_exec(relay_ip, relay_user,
            f"ss -tlnp 2>/dev/null | grep :{REVERSE_TUNNEL_PORT} || echo NOTLISTENING")
        if "NOTLISTENING" in stdout or str(REVERSE_TUNNEL_PORT) not in (stdout or ""):
            warn(f"Port {REVERSE_TUNNEL_PORT} NOT listening on relay.")
            warn("Field Unit must run: python3 tunnel_tool.py --field-unit")
            if not ask_yes_no("Continue anyway?", default=True): sys.exit(0)
        else: info(f"Reverse tunnel detected on relay:{REVERSE_TUNNEL_PORT}")

        # Phase 5: Field Unit user
        field_user = cfg.get("field_unit_user")
        if not field_user:
            field_user = ask_input(f"SSH user on Field Unit (default: {DEFAULT_SSH_USER})") or DEFAULT_SSH_USER
            cfg["field_unit_user"] = field_user; save_config(cfg)

        # Phase 6: Cross-node keying to Field Unit
        step("Ensuring key access to Field Unit through relay")
        jump_cmd = ["ssh",*base_ssh_opts(),"-o","BatchMode=yes",
                    "-J",f"{relay_user}@{relay_ip}","-p",str(REVERSE_TUNNEL_PORT),
                    f"{field_user}@localhost","echo OK"]
        rc, stdout, _ = run_cmd(jump_cmd, timeout=30)
        if rc != 0 or "OK" not in (stdout or ""):
            warn("Cannot reach Field Unit with keys. Setting up cross-node keying...")
            relay_pub = ensure_remote_key(relay_ip, relay_user, password=relay_pw)
            local_pub = get_pub_key()
            field_pw = ask_input(f"Password for {field_user} on Field Unit (one-time key setup)", secret=True)
            if field_pw and relay_pub:
                # Ensure sshpass on relay
                dim("Ensuring sshpass on relay...")
                remote_exec(relay_ip, relay_user,
                    "which sshpass >/dev/null 2>&1 || (apt-get install -y sshpass 2>/dev/null || yum install -y sshpass 2>/dev/null)")
                for pub, label in [(relay_pub, "relay"), (local_pub, "local")]:
                    escaped = pub.replace('"', '\\"').replace("'", "'\\''")
                    inject = (f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
                              f"grep -qF '{pub}' ~/.ssh/authorized_keys 2>/dev/null || "
                              f"echo '{pub}' >> ~/.ssh/authorized_keys && "
                              f"chmod 600 ~/.ssh/authorized_keys")
                    relay_run = (f'sshpass -p "{field_pw}" ssh -o StrictHostKeyChecking=accept-new '
                                 f'-o UserKnownHostsFile=~/.ssh/{TOOL_NAME}_known_hosts '
                                 f'-o PubkeyAuthentication=no '
                                 f'-p {REVERSE_TUNNEL_PORT} {field_user}@localhost "{inject}"')
                    rc2, _, err2 = remote_exec(relay_ip, relay_user, relay_run, timeout=30)
                    if rc2 == 0: info(f"{label} key pushed to Field Unit")
                    else: warn(f"{label} key push may have failed: {err2[:80] if err2 else 'unknown'}")
        else: info("Field Unit reachable with keys through relay")

        # Phase 7: Iran Server (Node D)
        iran_ip = ""; iran_user = ""
        if ask_yes_no("Set up connection to Iran Server (Node D)?", default=True):
            iran_ip = cfg.get("iran_server",{}).get("ip","") or ask_input("Iran Server IP (Node D)")
            iran_user = (cfg.get("iran_server",{}).get("user","")
                         or ask_input(f"SSH user for Iran Server (default: {DEFAULT_SSH_USER})")
                         or DEFAULT_SSH_USER)
            cfg["iran_server"] = {"ip":iran_ip,"user":iran_user}; save_config(cfg)
            step("Field Unit -> Iran Server keying")
            iran_pw = ask_input(f"Password for {iran_user}@{iran_ip}", secret=True)
            if iran_pw:
                fu_keygen = ["ssh",*base_ssh_opts(),"-J",f"{relay_user}@{relay_ip}",
                             "-p",str(REVERSE_TUNNEL_PORT),f"{field_user}@localhost",
                             (f'test -f ~/.ssh/{KEY_NAME} || ssh-keygen -t rsa -b 4096 '
                              f'-f ~/.ssh/{KEY_NAME} -N "" -C "{TOOL_NAME}@field-unit" 2>/dev/null; '
                              f'cat ~/.ssh/{KEY_NAME}.pub')]
                rc, fu_pub, _ = run_cmd(fu_keygen, timeout=30)
                if rc == 0 and fu_pub.strip():
                    info("Field Unit key obtained")
                    escaped = fu_pub.strip().replace("'", "'\\''")
                    push_iran = ["ssh",*base_ssh_opts(),"-J",f"{relay_user}@{relay_ip}",
                                 "-p",str(REVERSE_TUNNEL_PORT),f"{field_user}@localhost",
                                 (f'sshpass -p "{iran_pw}" ssh -o StrictHostKeyChecking=accept-new '
                                  f"{iran_user}@{iran_ip} "
                                  f"\"mkdir -p ~/.ssh && echo '{escaped}' >> ~/.ssh/authorized_keys && "
                                  f'chmod 600 ~/.ssh/authorized_keys" 2>&1 || echo SSHPASS_MISSING')]
                    rc2, out2, _ = run_cmd(push_iran, timeout=45)
                    if "SSHPASS_MISSING" in out2:
                        warn("sshpass not on Field Unit. Run --field-unit first to install deps via relay.")
                    elif rc2 == 0: info("Field Unit -> Iran Server keying done")
                    else: warn("Key push may have failed")

        # Phase 8: Unfiltered mode
        socks_proc = None
        if args.unfiltered:
            step("=== UNFILTERED MODE ===")
            socks_cmd = ["ssh",*base_ssh_opts(),"-N",
                         "-D",f"127.0.0.1:{SOCKS_PROXY_PORT}",
                         "-o","ExitOnForwardFailure=yes",
                         "-J",f"{relay_user}@{relay_ip}",
                         "-p",str(REVERSE_TUNNEL_PORT),f"{field_user}@localhost"]
            socks_proc = spawn_background(socks_cmd)
            time.sleep(3)
            if socks_proc.poll() is not None:
                _, stderr = socks_proc.communicate()
                error(f"SOCKS proxy failed: {_friendly_err(stderr)}"); socks_proc = None
            else: info(f"SOCKS5 proxy on 127.0.0.1:{SOCKS_PROXY_PORT}")
            if iran_ip and ask_yes_no("Also test Iran Server reachability?"):
                test_iran = ["ssh",*base_ssh_opts(),"-o","BatchMode=yes",
                             "-J",f"{relay_user}@{relay_ip},{field_user}@localhost:{REVERSE_TUNNEL_PORT}",
                             f"{iran_user}@{iran_ip}","echo OK"]
                rc, stdout, _ = run_cmd(test_iran, timeout=45)
                if rc == 0 and "OK" in (stdout or ""): info("Iran Server reachable through chain")
                else: warn("Iran Server not reachable")

        # Phase 9: Success
        print_success_banner(relay_ip, relay_user, field_user, iran_ip, iran_user, unfiltered=args.unfiltered)
        generate_ssh_config(relay_ip, relay_user, field_user, iran_ip, iran_user)

        if socks_proc:
            info("SOCKS proxy running. Ctrl+C to disconnect.")
            try:
                while True:
                    if socks_proc.poll() is not None: warn("SOCKS proxy dropped!"); break
                    time.sleep(5)
            except KeyboardInterrupt: signal_handler(signal.SIGINT, None)

        info("Setup complete.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: signal_handler(signal.SIGINT, None)
    except Exception as e:
        error(f"Unexpected error: {e}")
        log(f"Fatal: {e}", "ERROR")
        import traceback; log(traceback.format_exc(), "ERROR")
        cleanup(); sys.exit(1)

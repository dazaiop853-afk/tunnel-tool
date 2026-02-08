#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║                    TunnelTool v1.0.0                             ║
║       Multi-Hop Reverse SSH Tunnel Manager                       ║
║                                                                  ║
║  Deploy: curl -sL <CDN_URL> | python3 - [-u]                    ║
╚══════════════════════════════════════════════════════════════════╝

Architecture:
  Node A (USA PC) ──► Node B (Germany Relay) ◄── Node C (Iran Field Unit)
                                                      │
                                                      ▼
                                                 Node D (Iran Server)

Goal 1: A → B → C  (reverse tunnel through relay)
Goal 2: A → B → C → D  (chain through field unit to Iran server)
"""

__version__ = "1.0.0"
__source_url__ = "https://raw.githubusercontent.com/dazaiop853-afk/tunneltool/main/tunnel_tool.py"
__cdn_url__ = "https://cdn.jsdelivr.net/gh/dazaiop853-afk/tunneltool@main/tunnel_tool.py"

import sys
import os
import signal
import subprocess
import shutil
import time
import json
import hashlib
import re
import atexit
import argparse
import getpass
import socket
import threading
import tempfile
from pathlib import Path
from typing import Optional, List, Tuple, Dict

# ─────────────────────────────────────────────────────────────────
# GLOBALS & CONSTANTS
# ─────────────────────────────────────────────────────────────────

TOOL_NAME = "tunneltool"
CONFIG_DIR = Path.home() / f".{TOOL_NAME}"
CONFIG_FILE = CONFIG_DIR / "config.json"
KNOWN_HOSTS_FILE = CONFIG_DIR / "known_hosts"
KEY_NAME = f"id_rsa_{TOOL_NAME}"
LOCAL_KEY_PATH = CONFIG_DIR / KEY_NAME
LOG_FILE = CONFIG_DIR / "tunnel.log"

REVERSE_TUNNEL_PORT = 2222
SOCKS_PROXY_PORT = 1080
SSH_ALIVE_INTERVAL = 15
SSH_ALIVE_COUNT_MAX = 3
CONNECTION_TIMEOUT = 20
GFW_CONNECTION_TIMEOUT = 45

DEFAULT_SSH_USER = "root"

# Iran-friendly PyPI mirrors
IRAN_PIP_MIRRORS = [
    "https://mirror-pypi.runflare.com/simple/",
    "https://pypi.tuna.tsinghua.edu.cn/simple/",
    "https://mirrors.aliyun.com/pypi/simple/",
]

CHILD_PROCESSES: List[subprocess.Popen] = []
TEMP_FILES: List[str] = []

# ANSI Colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    DIM = "\033[2m"

# ─────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    """Write to log file and optionally print."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [{level}] {msg}\n")

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║                   🔒 TunnelTool v{__version__:<24s}     ║
║            Multi-Hop Reverse SSH Tunnel Manager              ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

def info(msg):    print(f"  {C.GREEN}✓{C.RESET} {msg}")
def warn(msg):    print(f"  {C.YELLOW}⚠{C.RESET} {msg}")
def error(msg):   print(f"  {C.RED}✗{C.RESET} {msg}")
def step(msg):    print(f"\n{C.BLUE}{C.BOLD}▸ {msg}{C.RESET}")
def dim(msg):     print(f"  {C.DIM}{msg}{C.RESET}")

def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        resp = input(f"  {C.YELLOW}?{C.RESET} {prompt}{suffix}").strip().lower()
        if resp == "":
            return default
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False

def ask_input(prompt: str, secret: bool = False) -> str:
    if secret:
        return getpass.getpass(f"  {C.YELLOW}?{C.RESET} {prompt}: ")
    return input(f"  {C.YELLOW}?{C.RESET} {prompt}: ").strip()

def detect_os() -> str:
    """Return 'macos' or 'linux'."""
    import platform
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    return "linux"

def run_cmd(cmd: List[str], timeout: int = 60, capture: bool = True,
            suppress_errors: bool = False) -> Tuple[int, str, str]:
    """Run a command with timeout. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            text=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        if not suppress_errors:
            log(f"run_cmd error: {e}", "ERROR")
        return -3, "", str(e)

def spawn_background(cmd: List[str]) -> subprocess.Popen:
    """Spawn a background process and track it for cleanup."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    CHILD_PROCESSES.append(proc)
    return proc

# ─────────────────────────────────────────────────────────────────
# SIGNAL HANDLING & CLEANUP
# ─────────────────────────────────────────────────────────────────

def cleanup():
    """Kill all child processes and remove temp files."""
    for proc in CHILD_PROCESSES:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    for f in TEMP_FILES:
        try:
            os.unlink(f)
        except Exception:
            pass

def signal_handler(signum, frame):
    signame = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
    print(f"\n\n  {C.YELLOW}⚠{C.RESET} Caught {signame}. Cleaning up...")
    cleanup()
    print(f"  {C.GREEN}✓{C.RESET} All tunnels and child processes terminated.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(cleanup)

# ─────────────────────────────────────────────────────────────────
# DEPENDENCY BOOTSTRAP
# ─────────────────────────────────────────────────────────────────

def check_python_dep(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def install_pip_package(package: str, use_iran_mirrors: bool = False):
    """Install a pip package, optionally trying Iran-friendly mirrors."""
    step(f"Installing Python package: {package}")
    base_cmd = [sys.executable, "-m", "pip", "install", "--user", "--quiet", package]

    if use_iran_mirrors:
        for mirror in IRAN_PIP_MIRRORS:
            info(f"Trying mirror: {mirror}")
            cmd = base_cmd + ["-i", mirror, "--trusted-host", mirror.split("//")[1].split("/")[0]]
            rc, _, stderr = run_cmd(cmd, timeout=120)
            if rc == 0:
                info(f"{package} installed via {mirror}")
                return True
            dim(f"Mirror failed, trying next...")
        # Fallback to default
        rc, _, _ = run_cmd(base_cmd, timeout=120)
        return rc == 0
    else:
        rc, _, stderr = run_cmd(base_cmd, timeout=120)
        if rc == 0:
            info(f"{package} installed successfully")
            return True
        error(f"Failed to install {package}: {stderr.strip()}")
        return False

def ensure_system_tool(tool: str):
    """Ensure a system tool like sshpass is installed."""
    if shutil.which(tool):
        return True

    step(f"Installing system tool: {tool}")
    os_type = detect_os()

    if os_type == "macos":
        if shutil.which("brew"):
            # sshpass is not in default brew, need special tap
            if tool == "sshpass":
                run_cmd(["brew", "install", "hudochenkov/sshpass/sshpass"], timeout=120)
            else:
                run_cmd(["brew", "install", tool], timeout=120)
        else:
            error("Homebrew not found. Please install it: https://brew.sh")
            return False
    else:
        # Linux
        warn(f"Need sudo to install {tool}")
        rc, _, _ = run_cmd(["sudo", "apt-get", "install", "-y", tool], timeout=120)
        if rc != 0:
            # Try yum as fallback
            run_cmd(["sudo", "yum", "install", "-y", tool], timeout=120)

    return shutil.which(tool) is not None

def bootstrap_dependencies(is_field_unit: bool = False):
    """Check and install all required dependencies."""
    step("Checking dependencies")

    # System tools
    tools = ["ssh", "ssh-keygen", "ssh-copy-id", "sshpass"]
    for tool in tools:
        if shutil.which(tool):
            dim(f"{tool}: found")
        else:
            if tool in ("ssh", "ssh-keygen", "ssh-copy-id"):
                error(f"Critical tool '{tool}' not found. Please install OpenSSH.")
                sys.exit(1)
            else:
                if not ensure_system_tool(tool):
                    warn(f"Could not install {tool}. Will fall back to paramiko if available.")
                    install_pip_package("paramiko", use_iran_mirrors=is_field_unit)

    info("All dependencies satisfied")

# ─────────────────────────────────────────────────────────────────
# SELF-UPDATE MECHANISM
# ─────────────────────────────────────────────────────────────────

def check_for_updates():
    """Check source URL for a newer version."""
    step("Checking for updates")
    try:
        import urllib.request
        req = urllib.request.Request(__source_url__, method='GET')
        req.add_header('User-Agent', f'TunnelTool/{__version__}')
        with urllib.request.urlopen(req, timeout=10) as resp:
            remote_source = resp.read().decode('utf-8')

        match = re.search(r'__version__\s*=\s*"([^"]+)"', remote_source)
        if match:
            remote_version = match.group(1)
            if remote_version != __version__:
                warn(f"New version available: v{remote_version} (current: v{__version__})")
                if ask_yes_no("Update by re-running the curl command?"):
                    info("Please re-run: curl -sL <CDN_URL> | python3 -")
                    sys.exit(0)
                else:
                    info("Continuing with current version")
            else:
                info(f"Up to date (v{__version__})")
        else:
            dim("Could not parse remote version, skipping")
    except Exception as e:
        dim(f"Update check skipped (offline or unreachable): {e}")

# ─────────────────────────────────────────────────────────────────
# STATE MANAGEMENT
# ─────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def wipe_config():
    """Wipe all config except SSH keys if they exist."""
    step("Wiping configuration")
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        info("Config file removed")
    if KNOWN_HOSTS_FILE.exists():
        KNOWN_HOSTS_FILE.unlink()
        info("Known hosts file removed")
    if LOG_FILE.exists():
        LOG_FILE.unlink()
        info("Log file removed")
    # Keep SSH keys unless user wants them gone too
    if LOCAL_KEY_PATH.exists():
        if ask_yes_no("SSH keys exist. Remove them too?", default=False):
            LOCAL_KEY_PATH.unlink()
            Path(str(LOCAL_KEY_PATH) + ".pub").unlink(missing_ok=True)
            info("SSH keys removed")
        else:
            info("SSH keys preserved")
    info("Wipe complete — fresh start")

def fresh_start_prompt():
    step("State Management")
    if CONFIG_DIR.exists() and any(CONFIG_DIR.iterdir()):
        if ask_yes_no("Wipe all existing configs and start fresh?", default=False):
            wipe_config()

# ─────────────────────────────────────────────────────────────────
# SSH KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────

def ensure_local_keys() -> Path:
    """Generate local SSH keys if they don't exist."""
    step("Key Management (Local)")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    pub_key = Path(str(LOCAL_KEY_PATH) + ".pub")

    if LOCAL_KEY_PATH.exists() and pub_key.exists():
        info(f"Keys exist: {LOCAL_KEY_PATH.name}")
        return LOCAL_KEY_PATH

    info("Generating new SSH key pair...")
    rc, _, stderr = run_cmd([
        "ssh-keygen", "-t", "rsa", "-b", "4096",
        "-f", str(LOCAL_KEY_PATH),
        "-N", "",  # No passphrase
        "-C", f"{TOOL_NAME}@{socket.gethostname()}",
    ], timeout=30)

    if rc != 0:
        error(f"Key generation failed: {stderr.strip()}")
        sys.exit(1)

    os.chmod(LOCAL_KEY_PATH, 0o600)
    info(f"Key generated: {LOCAL_KEY_PATH.name}")
    return LOCAL_KEY_PATH

def get_pub_key_content() -> str:
    pub_path = Path(str(LOCAL_KEY_PATH) + ".pub")
    return pub_path.read_text().strip()

# ─────────────────────────────────────────────────────────────────
# COMMON SSH OPTIONS
# ─────────────────────────────────────────────────────────────────

def base_ssh_opts() -> List[str]:
    """Return common SSH options for all connections."""
    return [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
        "-o", f"ServerAliveInterval={SSH_ALIVE_INTERVAL}",
        "-o", f"ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}",
        "-o", "ConnectTimeout=20",
        "-o", "LogLevel=ERROR",
        "-i", str(LOCAL_KEY_PATH),
    ]

def base_ssh_opts_no_key() -> List[str]:
    """SSH options without identity file (for password auth)."""
    return [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
        "-o", f"ServerAliveInterval={SSH_ALIVE_INTERVAL}",
        "-o", f"ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}",
        "-o", "ConnectTimeout=20",
        "-o", "LogLevel=ERROR",
    ]

# ─────────────────────────────────────────────────────────────────
# KNOWN HOSTS MANAGEMENT
# ─────────────────────────────────────────────────────────────────

def remove_host_from_known_hosts(host: str, port: int = 22):
    """Remove a host entry from our sandboxed known_hosts."""
    if not KNOWN_HOSTS_FILE.exists():
        return
    run_cmd([
        "ssh-keygen", "-f", str(KNOWN_HOSTS_FILE),
        "-R", f"[{host}]:{port}" if port != 22 else host,
    ], timeout=10, suppress_errors=True)

# ─────────────────────────────────────────────────────────────────
# CONNECTION TESTING & HEALTH CHECKS
# ─────────────────────────────────────────────────────────────────

def test_key_auth(host: str, user: str, port: int = 22, timeout: int = CONNECTION_TIMEOUT) -> bool:
    """Test if key-based auth works (BatchMode to avoid hanging on password prompt)."""
    cmd = [
        "ssh",
        *base_ssh_opts(),
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
        f"{user}@{host}",
        "echo OK",
    ]
    rc, stdout, _ = run_cmd(cmd, timeout=timeout + 10)
    return rc == 0 and "OK" in stdout

def test_password_auth(host: str, user: str, password: str,
                       port: int = 22, timeout: int = CONNECTION_TIMEOUT) -> bool:
    """Test password-based SSH connection using sshpass."""
    if not shutil.which("sshpass"):
        error("sshpass not available for password authentication")
        return False

    cmd = [
        "sshpass", "-p", password,
        "ssh",
        *base_ssh_opts_no_key(),
        "-o", f"ConnectTimeout={timeout}",
        "-o", "PubkeyAuthentication=no",
        "-p", str(port),
        f"{user}@{host}",
        "echo OK",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=timeout + 15)

    if rc == 0 and "OK" in stdout:
        return True

    # Handle host key changed
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr or "Host key verification failed" in stderr:
        warn("Remote host key has changed — auto-fixing...")
        remove_host_from_known_hosts(host, port)
        # Retry
        rc, stdout, _ = run_cmd(cmd, timeout=timeout + 15)
        return rc == 0 and "OK" in stdout

    return False

def copy_key_to_host(host: str, user: str, password: str,
                     port: int = 22, timeout: int = CONNECTION_TIMEOUT) -> bool:
    """Copy local public key to remote host using sshpass + ssh-copy-id."""
    step(f"Copying key to {user}@{host}:{port}")

    if not shutil.which("sshpass"):
        error("sshpass required for key distribution")
        return False

    pub_key = str(LOCAL_KEY_PATH) + ".pub"

    cmd = [
        "sshpass", "-p", password,
        "ssh-copy-id",
        "-i", pub_key,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
        f"{user}@{host}",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=timeout + 15)

    # Handle host key changed
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
        warn("Host key changed — auto-fixing and retrying...")
        remove_host_from_known_hosts(host, port)
        rc, stdout, stderr = run_cmd(cmd, timeout=timeout + 15)

    if rc == 0:
        info(f"Key copied to {host}")
        return True

    error(f"Key copy failed: {_friendly_ssh_error(stderr)}")
    return False

def _friendly_ssh_error(stderr: str) -> str:
    """Convert raw SSH errors into user-friendly messages."""
    stderr_lower = stderr.lower()
    if "connection refused" in stderr_lower:
        return "Connection refused — SSH service may not be running on the target"
    if "connection timed out" in stderr_lower or "timed out" in stderr_lower:
        return "Connection timed out — host may be unreachable or blocked by a firewall"
    if "permission denied" in stderr_lower:
        return "Permission denied — wrong password or key"
    if "no route to host" in stderr_lower:
        return "No route to host — network unreachable"
    if "host key verification failed" in stderr_lower:
        return "Host key mismatch — will attempt auto-fix"
    if "name or service not known" in stderr_lower:
        return "Hostname could not be resolved"
    cleaned = stderr.strip().split("\n")[-1] if stderr.strip() else "Unknown error"
    return cleaned

# ─────────────────────────────────────────────────────────────────
# INTERACTIVE HOST SETUP
# ─────────────────────────────────────────────────────────────────

def get_host_credentials(node_name: str, config_key: str, cfg: dict,
                         timeout: int = CONNECTION_TIMEOUT) -> Tuple[str, str, str]:
    """
    Get host IP, user, and password. Uses saved config if available.
    Returns (ip, user, password).
    """
    step(f"Setting up {node_name}")

    # Check saved config
    saved = cfg.get(config_key)
    if saved:
        ip = saved.get("ip", "")
        user = saved.get("user", DEFAULT_SSH_USER)
        info(f"Found saved config: {user}@{ip}")

        # Test if key auth works
        if test_key_auth(ip, user, timeout=timeout):
            info(f"Key auth working for {ip}")
            return ip, user, ""

        warn(f"Saved IP {ip} not reachable with keys. Need password or new IP.")
        if not ask_yes_no(f"Try {ip} with a password?", default=True):
            # Remove stale config
            del cfg[config_key]
            save_config(cfg)
            return _prompt_new_host(node_name, config_key, cfg, timeout)

        password = ask_input(f"Password for {user}@{ip}", secret=True)
        if not _confirm_password(password):
            password = ask_input(f"Password for {user}@{ip} (re-enter)", secret=True)

        if test_password_auth(ip, user, password, timeout=timeout):
            info(f"{ip} is healthy ✓")
            return ip, user, password
        else:
            error(f"Cannot reach {node_name} at {ip}")
            del cfg[config_key]
            save_config(cfg)
            return _prompt_new_host(node_name, config_key, cfg, timeout)

    return _prompt_new_host(node_name, config_key, cfg, timeout)

def _prompt_new_host(node_name: str, config_key: str, cfg: dict,
                     timeout: int) -> Tuple[str, str, str]:
    """Prompt user for new host details with health check loop."""
    max_attempts = 3
    for attempt in range(max_attempts):
        ip = ask_input(f"IP address for {node_name}")
        user = ask_input(f"SSH user for {node_name} (default: {DEFAULT_SSH_USER})") or DEFAULT_SSH_USER
        password = ask_input(f"Password for {user}@{ip}", secret=True)

        if not _confirm_password(password):
            password = ask_input(f"Password (re-enter)", secret=True)

        dim(f"Testing connection to {user}@{ip}...")

        # First try key auth
        if test_key_auth(ip, user, timeout=timeout):
            info(f"{ip} is healthy (key auth) ✓")
            cfg[config_key] = {"ip": ip, "user": user}
            save_config(cfg)
            return ip, user, password

        # Then try password
        if test_password_auth(ip, user, password, timeout=timeout):
            info(f"{ip} is healthy ✓")
            cfg[config_key] = {"ip": ip, "user": user}
            save_config(cfg)
            return ip, user, password

        error(f"IP unhealthy — cannot reach {ip}")
        if attempt < max_attempts - 1:
            warn("Please enter a new IP")

    error(f"Could not establish connection to {node_name} after {max_attempts} attempts")
    sys.exit(1)

def _confirm_password(password: str) -> bool:
    return ask_yes_no("Did you enter the password correctly?", default=True)

# ─────────────────────────────────────────────────────────────────
# REMOTE KEY GENERATION & CROSS-NODE KEYING
# ─────────────────────────────────────────────────────────────────

def remote_exec(host: str, user: str, cmd_str: str, port: int = 22,
                timeout: int = 30, password: str = "") -> Tuple[int, str, str]:
    """Execute a command on a remote host via SSH."""
    if password and not test_key_auth(host, user, port, timeout=10):
        ssh_cmd = [
            "sshpass", "-p", password,
            "ssh",
            *base_ssh_opts_no_key(),
            "-p", str(port),
            f"{user}@{host}",
            cmd_str,
        ]
    else:
        ssh_cmd = [
            "ssh",
            *base_ssh_opts(),
            "-p", str(port),
            f"{user}@{host}",
            cmd_str,
        ]
    return run_cmd(ssh_cmd, timeout=timeout)

def ensure_remote_key(host: str, user: str, port: int = 22,
                      password: str = "", key_name: str = KEY_NAME) -> Optional[str]:
    """Ensure an SSH key exists on a remote host. Returns the public key content."""
    step(f"Ensuring SSH key on {user}@{host}")

    check_cmd = f'test -f ~/.ssh/{key_name} && cat ~/.ssh/{key_name}.pub || echo "NOKEY"'
    rc, stdout, _ = remote_exec(host, user, check_cmd, port, password=password)

    if rc == 0 and "NOKEY" not in stdout and stdout.strip():
        info(f"Key exists on {host}")
        return stdout.strip()

    # Generate key remotely
    info(f"Generating key on {host}...")
    gen_cmd = (
        f'ssh-keygen -t rsa -b 4096 -f ~/.ssh/{key_name} -N "" '
        f'-C "{TOOL_NAME}@{host}" 2>/dev/null && cat ~/.ssh/{key_name}.pub'
    )
    rc, stdout, stderr = remote_exec(host, user, gen_cmd, port, timeout=30, password=password)

    if rc == 0 and stdout.strip():
        info(f"Key generated on {host}")
        return stdout.strip()

    error(f"Failed to generate key on {host}: {stderr.strip()}")
    return None

def push_key_to_remote(target_host: str, target_user: str, pub_key: str,
                       target_port: int = 22, password: str = "") -> bool:
    """Add a public key to a remote host's authorized_keys."""
    step(f"Pushing key to {target_user}@{target_host}")

    escaped_key = pub_key.replace('"', '\\"')
    cmd = (
        f'mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
        f'grep -qF "{escaped_key}" ~/.ssh/authorized_keys 2>/dev/null || '
        f'echo "{escaped_key}" >> ~/.ssh/authorized_keys && '
        f'chmod 600 ~/.ssh/authorized_keys'
    )

    rc, _, stderr = remote_exec(target_host, target_user, cmd, target_port, password=password)
    if rc == 0:
        info(f"Key authorized on {target_host}")
        return True
    error(f"Key push failed: {stderr.strip()}")
    return False

def cross_node_key_setup(source_host: str, source_user: str,
                         target_host: str, target_user: str,
                         source_password: str = "", target_password: str = "",
                         source_port: int = 22, target_port: int = 22):
    """
    Generate key on source, copy pubkey to target's authorized_keys.
    This enables password-less SSH from source → target.
    """
    step(f"Cross-node keying: {source_host} → {target_host}")

    # Get/generate key on source
    pub_key = ensure_remote_key(source_host, source_user, source_port, password=source_password)
    if not pub_key:
        error("Could not obtain source key")
        return False

    # Push to target
    return push_key_to_remote(target_host, target_user, pub_key, target_port, password=target_password)

# ─────────────────────────────────────────────────────────────────
# PORT MANAGEMENT
# ─────────────────────────────────────────────────────────────────

def kill_port_holder(host: str, user: str, port: int, ssh_port: int = 22, password: str = ""):
    """Kill any process holding a specific port on a remote host."""
    step(f"Checking port {port} on {host}")

    cmd = f"lsof -ti :{port} 2>/dev/null"
    rc, stdout, _ = remote_exec(host, user, cmd, ssh_port, password=password)

    if rc == 0 and stdout.strip():
        pids = stdout.strip().split("\n")
        warn(f"Port {port} is busy (PID: {', '.join(pids)}). Killing...")
        kill_cmd = f"kill -9 {' '.join(pids)} 2>/dev/null"
        remote_exec(host, user, kill_cmd, ssh_port, password=password)
        time.sleep(1)
        # Verify
        rc2, stdout2, _ = remote_exec(host, user, cmd, ssh_port, password=password)
        if rc2 == 0 and stdout2.strip():
            error(f"Could not free port {port}")
            return False
        info(f"Port {port} freed")
    else:
        info(f"Port {port} is available")
    return True

# ─────────────────────────────────────────────────────────────────
# TUNNEL ESTABLISHMENT
# ─────────────────────────────────────────────────────────────────

def establish_reverse_tunnel(relay_host: str, relay_user: str,
                             relay_port: int = 22) -> Optional[subprocess.Popen]:
    """
    Establish reverse SSH tunnel: Field Unit → Relay
    Maps relay:2222 → Field Unit:22
    This is run conceptually FROM the field unit, but we set it up
    by commanding the field unit remotely.
    """
    step(f"Establishing reverse tunnel via {relay_host}")

    # The reverse tunnel SSH command to run ON the field unit
    # -R 2222:localhost:22 means relay:2222 → fieldunit:22
    cmd = [
        "ssh",
        *base_ssh_opts(),
        "-N",  # No remote command
        "-R", f"{REVERSE_TUNNEL_PORT}:localhost:22",
        "-o", "ExitOnForwardFailure=yes",
        "-p", str(relay_port),
        f"{relay_user}@{relay_host}",
    ]

    info(f"Tunnel: {relay_host}:{REVERSE_TUNNEL_PORT} ← localhost:22")
    proc = spawn_background(cmd)

    # Wait and verify
    time.sleep(3)
    if proc.poll() is not None:
        _, stderr = proc.communicate()
        error(f"Tunnel failed to start: {_friendly_ssh_error(stderr)}")
        return None

    info("Reverse tunnel established ✓")
    return proc

def establish_forward_tunnel_socks(target_host: str, target_user: str,
                                   target_port: int = 22,
                                   socks_port: int = SOCKS_PROXY_PORT) -> Optional[subprocess.Popen]:
    """Establish a SOCKS5 dynamic port forward."""
    step(f"Setting up SOCKS5 proxy via {target_host}")

    cmd = [
        "ssh",
        *base_ssh_opts(),
        "-N",
        "-D", f"127.0.0.1:{socks_port}",
        "-o", "ExitOnForwardFailure=yes",
        "-p", str(target_port),
        f"{target_user}@{target_host}",
    ]

    proc = spawn_background(cmd)
    time.sleep(3)

    if proc.poll() is not None:
        _, stderr = proc.communicate()
        error(f"SOCKS proxy failed: {_friendly_ssh_error(stderr)}")
        return None

    info(f"SOCKS5 proxy active on 127.0.0.1:{socks_port}")
    return proc

# ─────────────────────────────────────────────────────────────────
# TUNNEL MONITORING
# ─────────────────────────────────────────────────────────────────

def monitor_tunnel(proc: subprocess.Popen, name: str):
    """Monitor a tunnel process in a background thread."""
    def _monitor():
        proc.wait()
        rc = proc.returncode
        if rc is not None and rc != 0:
            error(f"Tunnel '{name}' died (exit code {rc})")
        else:
            dim(f"Tunnel '{name}' exited cleanly")
    t = threading.Thread(target=_monitor, daemon=True)
    t.start()
    return t

# ─────────────────────────────────────────────────────────────────
# SUCCESS BANNER & CONFIG GENERATION
# ─────────────────────────────────────────────────────────────────

def print_success_banner(relay_ip: str, relay_user: str,
                         field_user: str, iran_server_ip: str = "",
                         iran_server_user: str = "",
                         unfiltered: bool = False):
    """Print the final success banner with copy-paste commands."""
    print(f"""
{C.GREEN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║                    ✅ SETUP COMPLETE                         ║
╠══════════════════════════════════════════════════════════════╣{C.RESET}
{C.CYAN}{C.BOLD}
  📡 GOAL 1: Connect to Field Unit (Iran Mac) via Relay
{C.RESET}
  {C.BOLD}Direct Jump:{C.RESET}
  {C.YELLOW}ssh -J {relay_user}@{relay_ip} -p {REVERSE_TUNNEL_PORT} \\
      -i {LOCAL_KEY_PATH} \\
      -o UserKnownHostsFile={KNOWN_HOSTS_FILE} \\
      {field_user}@localhost{C.RESET}

  {C.BOLD}Or equivalently:{C.RESET}
  {C.YELLOW}ssh -o ProxyCommand="ssh -W localhost:{REVERSE_TUNNEL_PORT} \\
      -i {LOCAL_KEY_PATH} {relay_user}@{relay_ip}" \\
      -i {LOCAL_KEY_PATH} \\
      -o UserKnownHostsFile={KNOWN_HOSTS_FILE} \\
      -p {REVERSE_TUNNEL_PORT} {field_user}@localhost{C.RESET}
""")

    if iran_server_ip:
        print(f"""{C.CYAN}{C.BOLD}
  📡 GOAL 2: Connect to Iran Server via Field Unit
{C.RESET}
  {C.YELLOW}ssh -J {relay_user}@{relay_ip},{field_user}@localhost:{REVERSE_TUNNEL_PORT} \\
      -i {LOCAL_KEY_PATH} \\
      -o UserKnownHostsFile={KNOWN_HOSTS_FILE} \\
      {iran_server_user}@{iran_server_ip}{C.RESET}
""")

    if unfiltered:
        print(f"""{C.MAGENTA}{C.BOLD}
  🌐 UNFILTERED MODE (SOCKS5 Proxy)
{C.RESET}
  {C.BOLD}Test your exit IP:{C.RESET}
  {C.YELLOW}export all_proxy=socks5h://127.0.0.1:{SOCKS_PROXY_PORT}
  curl ifconfig.me{C.RESET}

  {C.BOLD}Use with any app:{C.RESET}
  {C.YELLOW}export http_proxy=socks5h://127.0.0.1:{SOCKS_PROXY_PORT}
  export https_proxy=socks5h://127.0.0.1:{SOCKS_PROXY_PORT}{C.RESET}
""")

    print(f"""{C.GREEN}{C.BOLD}╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

def generate_ssh_config(relay_ip: str, relay_user: str,
                        field_user: str, iran_server_ip: str = "",
                        iran_server_user: str = ""):
    """Generate ~/.ssh/config snippet."""
    step("SSH Config Snippet (optional)")

    snippet = f"""
# ─── TunnelTool Generated Config ───
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
    if iran_server_ip:
        snippet += f"""
Host iran-server
    HostName {iran_server_ip}
    User {iran_server_user}
    ProxyJump field-unit
    IdentityFile {LOCAL_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval {SSH_ALIVE_INTERVAL}
    ServerAliveCountMax {SSH_ALIVE_COUNT_MAX}
"""

    snippet += "# ─── End TunnelTool Config ───\n"

    if ask_yes_no("Add these aliases to ~/.ssh/config? (ssh field-unit / ssh iran-server)"):
        ssh_config = Path.home() / ".ssh" / "config"
        ssh_config.parent.mkdir(parents=True, exist_ok=True)

        # Remove old TunnelTool config if present
        if ssh_config.exists():
            content = ssh_config.read_text()
            content = re.sub(
                r'# ─── TunnelTool Generated Config ───.*?# ─── End TunnelTool Config ───\n',
                '', content, flags=re.DOTALL
            )
            ssh_config.write_text(content + snippet)
        else:
            ssh_config.write_text(snippet)

        os.chmod(ssh_config, 0o600)
        info("SSH config updated. You can now use:")
        print(f"    {C.YELLOW}ssh field-unit{C.RESET}")
        if iran_server_ip:
            print(f"    {C.YELLOW}ssh iran-server{C.RESET}")
    else:
        info("Config snippet (copy manually if desired):")
        print(f"{C.DIM}{snippet}{C.RESET}")

# ─────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TunnelTool — Multi-Hop Reverse SSH Tunnel Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--unfiltered", action="store_true",
                        help="Enable SOCKS5 proxy for unfiltered internet access")
    parser.add_argument("--field-unit", action="store_true",
                        help="Run in Field Unit mode (initiate reverse tunnel FROM this machine)")
    parser.add_argument("--version", action="version", version=f"TunnelTool v{__version__}")

    args = parser.parse_args()

    print_banner()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KNOWN_HOSTS_FILE.touch(exist_ok=True)

    # ── Phase 0: Update check ──
    check_for_updates()

    # ── Phase 1: Dependencies ──
    bootstrap_dependencies(is_field_unit=args.field_unit)

    # ── Phase 2: Fresh start option ──
    fresh_start_prompt()

    # ── Phase 3: Local keys ──
    ensure_local_keys()

    cfg = load_config()

    # ════════════════════════════════════════════════════════
    # FIELD UNIT MODE (run on Node C in Iran)
    # ════════════════════════════════════════════════════════
    if args.field_unit:
        step("═══ FIELD UNIT MODE ═══")
        info("This machine will initiate a reverse tunnel to the Relay server.")

        # Get relay credentials
        relay_ip, relay_user, relay_pw = get_host_credentials(
            "Germany Relay (Node B)", "relay", cfg, timeout=GFW_CONNECTION_TIMEOUT
        )

        # Copy our key to relay
        if relay_pw:
            if not test_key_auth(relay_ip, relay_user, timeout=GFW_CONNECTION_TIMEOUT):
                copy_key_to_host(relay_ip, relay_user, relay_pw, timeout=GFW_CONNECTION_TIMEOUT)

        # Kill stale port holder
        kill_port_holder(relay_ip, relay_user, REVERSE_TUNNEL_PORT, password=relay_pw)

        # Establish reverse tunnel
        tunnel_proc = establish_reverse_tunnel(relay_ip, relay_user)
        if not tunnel_proc:
            error("Failed to establish reverse tunnel. Exiting.")
            sys.exit(1)

        monitor_tunnel(tunnel_proc, "reverse-tunnel")

        print(f"""
{C.GREEN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║          🔒 REVERSE TUNNEL ACTIVE                            ║
║                                                              ║
║   Relay:{relay_ip}:{REVERSE_TUNNEL_PORT} → This Machine:22{' ' * 14}║
║                                                              ║
║   Press Ctrl+C to disconnect.                                ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
""")

        # Keep alive
        try:
            while True:
                if tunnel_proc.poll() is not None:
                    warn("Tunnel dropped! Reconnecting in 5s...")
                    time.sleep(5)
                    kill_port_holder(relay_ip, relay_user, REVERSE_TUNNEL_PORT, password=relay_pw)
                    tunnel_proc = establish_reverse_tunnel(relay_ip, relay_user)
                    if tunnel_proc:
                        monitor_tunnel(tunnel_proc, "reverse-tunnel")
                    else:
                        error("Reconnection failed. Retrying in 30s...")
                        time.sleep(30)
                time.sleep(5)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)

    # ════════════════════════════════════════════════════════
    # CLIENT MODE (run on Node A in USA)
    # ════════════════════════════════════════════════════════
    else:
        step("═══ CLIENT MODE (USA PC) ═══")

        # ── Setup Relay (Node B) ──
        relay_ip, relay_user, relay_pw = get_host_credentials(
            "Germany Relay Server (Node B)", "relay", cfg
        )

        # Copy key to relay
        if relay_pw and not test_key_auth(relay_ip, relay_user):
            copy_key_to_host(relay_ip, relay_user, relay_pw)

        # Verify key auth now works
        if not test_key_auth(relay_ip, relay_user):
            error("Key auth to relay not working after key copy. Check manually.")
            sys.exit(1)
        info("Relay key auth confirmed ✓")

        # ── Check reverse tunnel from Field Unit ──
        step("Checking if Field Unit reverse tunnel is active on relay")
        rc, stdout, _ = remote_exec(
            relay_ip, relay_user,
            f"ss -tlnp | grep :{REVERSE_TUNNEL_PORT} || echo NOTLISTENING"
        )

        if "NOTLISTENING" in stdout or REVERSE_TUNNEL_PORT not in (stdout or ""):
            warn(f"Port {REVERSE_TUNNEL_PORT} is NOT listening on the relay.")
            warn("The Field Unit must run this script with --field-unit to establish the reverse tunnel.")
            print(f"""
  {C.YELLOW}On the Field Unit (Iran Mac), run:{C.RESET}
  {C.BOLD}curl -sL <CDN_URL> | python3 - --field-unit{C.RESET}
""")
            if not ask_yes_no("Continue anyway (tunnel may be established later)?", default=True):
                sys.exit(0)
        else:
            info(f"Reverse tunnel detected on relay port {REVERSE_TUNNEL_PORT} ✓")

        # ── Get Field Unit user ──
        field_user = cfg.get("field_unit_user")
        if not field_user:
            field_user = ask_input(f"SSH username on Field Unit (default: {DEFAULT_SSH_USER})") or DEFAULT_SSH_USER
            cfg["field_unit_user"] = field_user
            save_config(cfg)

        # ── Cross-node keying: Push local key to Field Unit via relay ──
        step("Ensuring key access to Field Unit through relay")
        # Test if we can already reach field unit through relay
        jump_test_cmd = [
            "ssh",
            *base_ssh_opts(),
            "-o", "BatchMode=yes",
            "-J", f"{relay_user}@{relay_ip}",
            "-p", str(REVERSE_TUNNEL_PORT),
            f"{field_user}@localhost",
            "echo OK",
        ]
        rc, stdout, _ = run_cmd(jump_test_cmd, timeout=30)

        if rc != 0 or "OK" not in (stdout or ""):
            warn("Cannot reach Field Unit with keys yet. Setting up cross-node keying...")

            # We need the relay to have a key to reach the field unit
            # Generate key on relay, get its pubkey
            relay_pub = ensure_remote_key(relay_ip, relay_user, password=relay_pw)

            if relay_pub:
                # Push relay's key to field unit via the reverse tunnel
                # Execute from relay: ssh-copy-id to localhost:2222
                info("Pushing relay key to Field Unit via reverse tunnel...")
                push_cmd = (
                    f'mkdir -p ~/.ssh && '
                    f'ssh -o StrictHostKeyChecking=accept-new '
                    f'-o UserKnownHostsFile=~/.ssh/{TOOL_NAME}_known_hosts '
                    f'-p {REVERSE_TUNNEL_PORT} {field_user}@localhost '
                    f'"mkdir -p ~/.ssh && echo \'{relay_pub}\' >> ~/.ssh/authorized_keys && '
                    f'chmod 600 ~/.ssh/authorized_keys"'
                )
                # This may need field unit password
                field_pw = ask_input(f"Password for {field_user} on Field Unit (for initial key setup)", secret=True)
                if field_pw:
                    push_cmd = (
                        f'sshpass -p "{field_pw}" ssh-copy-id '
                        f'-o StrictHostKeyChecking=accept-new '
                        f'-o UserKnownHostsFile=~/.ssh/{TOOL_NAME}_known_hosts '
                        f'-p {REVERSE_TUNNEL_PORT} '
                        f'{field_user}@localhost'
                    )
                    # Also copy our local key
                    local_pub = get_pub_key_content()
                    push_local_cmd = (
                        f'sshpass -p "{field_pw}" ssh '
                        f'-o StrictHostKeyChecking=accept-new '
                        f'-o UserKnownHostsFile=~/.ssh/{TOOL_NAME}_known_hosts '
                        f'-p {REVERSE_TUNNEL_PORT} '
                        f'{field_user}@localhost '
                        f'"mkdir -p ~/.ssh && echo \'{local_pub}\' >> ~/.ssh/authorized_keys && '
                        f'chmod 600 ~/.ssh/authorized_keys"'
                    )

                    # Execute on relay
                    remote_exec(relay_ip, relay_user, push_cmd, password=relay_pw, timeout=30)
                    remote_exec(relay_ip, relay_user, push_local_cmd, password=relay_pw, timeout=30)
                    info("Keys pushed to Field Unit through relay")
        else:
            info("Field Unit reachable with keys through relay ✓")

        # ── Goal 2: Iran Server (Node D) ──
        iran_server_ip = ""
        iran_server_user = ""
        if ask_yes_no("Set up connection to Iran Server (Node D) through Field Unit?", default=True):
            iran_server_ip = cfg.get("iran_server", {}).get("ip", "") or ask_input("Iran Server IP (Node D)")
            iran_server_user = (
                cfg.get("iran_server", {}).get("user", "")
                or ask_input(f"SSH user for Iran Server (default: {DEFAULT_SSH_USER})")
                or DEFAULT_SSH_USER
            )

            cfg["iran_server"] = {"ip": iran_server_ip, "user": iran_server_user}
            save_config(cfg)

            # Cross-key: Field Unit → Iran Server
            step("Setting up Field Unit → Iran Server keying")
            warn("This requires executing commands on the Field Unit to key into the Iran Server.")
            iran_pw = ask_input(f"Password for {iran_server_user}@{iran_server_ip}", secret=True)

            if iran_pw:
                # Execute on Field Unit (via relay jump) to generate key and push to Iran Server
                field_jump = f"-J {relay_user}@{relay_ip} -p {REVERSE_TUNNEL_PORT}"

                # Generate key on field unit
                fu_keygen_cmd = [
                    "ssh",
                    *base_ssh_opts(),
                    "-J", f"{relay_user}@{relay_ip}",
                    "-p", str(REVERSE_TUNNEL_PORT),
                    f"{field_user}@localhost",
                    f'test -f ~/.ssh/{KEY_NAME} || ssh-keygen -t rsa -b 4096 -f ~/.ssh/{KEY_NAME} -N "" -C "{TOOL_NAME}@field-unit" 2>/dev/null; cat ~/.ssh/{KEY_NAME}.pub',
                ]
                rc, fu_pub, _ = run_cmd(fu_keygen_cmd, timeout=30)

                if rc == 0 and fu_pub.strip():
                    info("Field Unit key obtained")
                    # Push Field Unit key to Iran Server (from Field Unit)
                    escaped_pub = fu_pub.strip().replace("'", "'\\''")
                    push_to_iran_cmd = [
                        "ssh",
                        *base_ssh_opts(),
                        "-J", f"{relay_user}@{relay_ip}",
                        "-p", str(REVERSE_TUNNEL_PORT),
                        f"{field_user}@localhost",
                        f'sshpass -p "{iran_pw}" ssh -o StrictHostKeyChecking=accept-new '
                        f'{iran_server_user}@{iran_server_ip} '
                        f'"mkdir -p ~/.ssh && echo \'{escaped_pub}\' >> ~/.ssh/authorized_keys && '
                        f'chmod 600 ~/.ssh/authorized_keys"',
                    ]
                    rc2, _, stderr2 = run_cmd(push_to_iran_cmd, timeout=45)
                    if rc2 == 0:
                        info("Field Unit → Iran Server keying complete ✓")
                    else:
                        warn(f"Key push may have failed: {_friendly_ssh_error(stderr2)}")

        # ── Unfiltered Mode ──
        socks_proc = None
        if args.unfiltered:
            step("═══ UNFILTERED MODE ═══")
            info("Setting up SOCKS5 proxy through the tunnel chain")

            # SOCKS via Jump Host to Field Unit
            socks_cmd = [
                "ssh",
                *base_ssh_opts(),
                "-N",
                "-D", f"127.0.0.1:{SOCKS_PROXY_PORT}",
                "-o", "ExitOnForwardFailure=yes",
                "-J", f"{relay_user}@{relay_ip}",
                "-p", str(REVERSE_TUNNEL_PORT),
                f"{field_user}@localhost",
            ]

            socks_proc = spawn_background(socks_cmd)
            time.sleep(3)

            if socks_proc.poll() is not None:
                _, stderr = socks_proc.communicate()
                error(f"SOCKS proxy failed: {_friendly_ssh_error(stderr)}")
                socks_proc = None
            else:
                info(f"SOCKS5 proxy active on 127.0.0.1:{SOCKS_PROXY_PORT}")

            # If also connecting to Iran Server with -u, set up proxy through Iran Server
            if iran_server_ip and ask_yes_no("Also set up unfiltered proxy via Iran Server?"):
                step("Setting up Iran Server → Relay reverse proxy for unfiltered access")
                # Generate key on Iran Server, push to Relay
                iran_jump_cmd = [
                    "ssh",
                    *base_ssh_opts(),
                    "-J", f"{relay_user}@{relay_ip},{field_user}@localhost:{REVERSE_TUNNEL_PORT}",
                    f"{iran_server_user}@{iran_server_ip}",
                ]
                # Test reachability
                test_cmd = iran_jump_cmd + ["echo OK"]
                rc, stdout, _ = run_cmd(test_cmd, timeout=45)
                if rc == 0 and "OK" in (stdout or ""):
                    info("Iran Server reachable through chain ✓")
                else:
                    warn("Iran Server not reachable through the tunnel chain")

        # ── Success ──
        print_success_banner(
            relay_ip, relay_user, field_user,
            iran_server_ip, iran_server_user,
            unfiltered=args.unfiltered,
        )

        generate_ssh_config(relay_ip, relay_user, field_user, iran_server_ip, iran_server_user)

        # Keep alive if tunnels are active
        if socks_proc:
            info("SOCKS proxy running. Press Ctrl+C to disconnect.")
            try:
                while True:
                    if socks_proc and socks_proc.poll() is not None:
                        warn("SOCKS proxy dropped!")
                        break
                    time.sleep(5)
            except KeyboardInterrupt:
                signal_handler(signal.SIGINT, None)

        info("Setup complete. Exiting.")

# ─────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        error(f"Unexpected error: {e}")
        log(f"Fatal: {e}", "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        cleanup()
        sys.exit(1)

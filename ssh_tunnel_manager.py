#!/usr/bin/env python3
"""
Advanced Multi-Hop SSH Tunnel Manager
Establishes resilient reverse SSH tunnels through censored networks
"""

import os
import sys
import subprocess
import json
import signal
import time
import argparse
import re
import socket
import getpass
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from urllib.request import urlopen
from urllib.error import URLError

# Script metadata
VERSION = "1.0.0"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/ssh_tunnel_manager.py"
CONFIG_DIR = Path.home() / ".ssh_tunnel_manager"
CONFIG_FILE = CONFIG_DIR / "config.json"
KNOWN_HOSTS_FILE = CONFIG_DIR / "known_hosts"
SSH_KEY_NAME = "id_rsa_tunneltool"
SSH_KEY_PATH = CONFIG_DIR / SSH_KEY_NAME
REVERSE_TUNNEL_PORT = 2222
SOCKS_PROXY_PORT = 1080

# Global process tracking for cleanup
child_processes = []

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner(message: str, color: str = Colors.OKGREEN):
    """Print a formatted banner message"""
    border = "=" * 70
    print(f"\n{color}{border}")
    print(f"{message.center(70)}")
    print(f"{border}{Colors.ENDC}\n")


def print_error(message: str):
    """Print an error message"""
    print(f"{Colors.FAIL}✗ ERROR: {message}{Colors.ENDC}")


def print_success(message: str):
    """Print a success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_info(message: str):
    """Print an info message"""
    print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")


def print_warning(message: str):
    """Print a warning message"""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def signal_handler(signum, frame):
    """Handle termination signals gracefully"""
    print_warning("\nReceived termination signal. Cleaning up...")
    cleanup_and_exit(0)


def cleanup_and_exit(exit_code: int = 0):
    """Clean up child processes and exit"""
    global child_processes
    
    for proc in child_processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            try:
                proc.kill()
            except:
                pass
    
    sys.exit(exit_code)


def detect_os() -> str:
    """Detect the operating system"""
    system = os.uname().sysname.lower()
    if 'darwin' in system:
        return 'macos'
    elif 'linux' in system:
        return 'linux'
    else:
        return 'unknown'


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH"""
    try:
        subprocess.run(['which', command], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def install_system_package(package: str, os_type: str) -> bool:
    """Install a system package using the appropriate package manager"""
    print_info(f"Installing system package: {package}")
    
    try:
        if os_type == 'macos':
            if not check_command_exists('brew'):
                print_error("Homebrew not found. Please install Homebrew first:")
                print_error('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
                return False
            subprocess.run(['brew', 'install', package], check=True)
        elif os_type == 'linux':
            print_info("This requires sudo privileges...")
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', package], check=True)
        else:
            print_error(f"Unsupported OS: {os_type}")
            return False
        
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install {package}: {e}")
        return False


def bootstrap_dependencies():
    """Check and install required dependencies"""
    print_banner("DEPENDENCY CHECK", Colors.OKCYAN)
    
    os_type = detect_os()
    print_info(f"Detected OS: {os_type}")
    
    # Check Python dependencies
    python_deps = ['paramiko']
    missing_python_deps = []
    
    for dep in python_deps:
        try:
            __import__(dep)
            print_success(f"Python package '{dep}' is installed")
        except ImportError:
            missing_python_deps.append(dep)
    
    # Install missing Python dependencies
    if missing_python_deps:
        print_info(f"Installing missing Python packages: {', '.join(missing_python_deps)}")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--user'] + missing_python_deps, 
                         check=True, capture_output=True)
            print_success("Python dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to install Python dependencies: {e}")
            return False
    
    # Check system dependencies
    if not check_command_exists('sshpass'):
        print_warning("sshpass not found")
        if not install_system_package('sshpass', os_type):
            print_error("Failed to install sshpass. Password automation will be limited.")
            return False
    else:
        print_success("sshpass is installed")
    
    # Ensure SSH is available
    if not check_command_exists('ssh'):
        print_error("SSH client not found. Please install OpenSSH.")
        return False
    
    print_success("All dependencies satisfied")
    return True


def check_for_updates() -> Optional[str]:
    """Check if a newer version is available"""
    try:
        print_info("Checking for updates...")
        response = urlopen(GITHUB_RAW_URL, timeout=5)
        remote_content = response.read().decode('utf-8')
        
        # Extract version from remote file
        version_match = re.search(r'VERSION\s*=\s*["\']([^"\']+)["\']', remote_content)
        if version_match:
            remote_version = version_match.group(1)
            if remote_version != VERSION:
                return remote_version
        
        print_success("You are running the latest version")
        return None
    except (URLError, Exception) as e:
        print_warning(f"Could not check for updates: {e}")
        return None


def prompt_update(new_version: str):
    """Prompt user to update the script"""
    print_warning(f"A new version ({new_version}) is available (current: {VERSION})")
    print_info("To update, simply rerun the curl command:")
    print(f"{Colors.BOLD}curl -sL {GITHUB_RAW_URL} | python3{Colors.ENDC}")
    
    response = input(f"\n{Colors.WARNING}Continue with current version? (yes/no): {Colors.ENDC}").strip().lower()
    if response not in ['yes', 'y']:
        print_info("Exiting. Please update and run again.")
        sys.exit(0)


def load_config() -> Dict:
    """Load configuration from file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print_warning("Config file corrupted. Starting fresh.")
            return {}
    return {}


def save_config(config: Dict):
    """Save configuration to file"""
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def wipe_config():
    """Wipe all configuration except SSH keys"""
    print_warning("Wiping configuration...")
    
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        print_success("Configuration file removed")
    
    if KNOWN_HOSTS_FILE.exists():
        KNOWN_HOSTS_FILE.unlink()
        print_success("Known hosts file removed")
    
    print_info(f"SSH keys at {SSH_KEY_PATH} preserved (will reuse if valid)")


def prompt_wipe():
    """Ask user if they want to wipe existing config"""
    if not CONFIG_FILE.exists() and not KNOWN_HOSTS_FILE.exists():
        return  # Nothing to wipe
    
    print_info("Existing configuration detected.")
    response = input(f"{Colors.WARNING}Do you wish to wipe all existing configs? (yes/no): {Colors.ENDC}").strip().lower()
    
    if response in ['yes', 'y']:
        wipe_config()


def get_user_input(prompt: str, confirm: bool = True, password: bool = False) -> str:
    """Get user input with optional confirmation"""
    while True:
        if password:
            value = getpass.getpass(f"{Colors.OKCYAN}{prompt}: {Colors.ENDC}")
        else:
            value = input(f"{Colors.OKCYAN}{prompt}: {Colors.ENDC}").strip()
        
        if not confirm:
            return value
        
        confirm_prompt = "Did you enter this correctly? (yes/no): "
        confirmation = input(f"{Colors.WARNING}{confirm_prompt}{Colors.ENDC}").strip().lower()
        
        if confirmation in ['yes', 'y']:
            return value
        else:
            print_info("Let's try again...")


def generate_ssh_key():
    """Generate SSH key pair if it doesn't exist"""
    if SSH_KEY_PATH.exists():
        print_success(f"SSH key already exists: {SSH_KEY_PATH}")
        return
    
    print_info("Generating SSH key pair...")
    CONFIG_DIR.mkdir(exist_ok=True, mode=0o700)
    
    try:
        subprocess.run([
            'ssh-keygen',
            '-t', 'rsa',
            '-b', '4096',
            '-f', str(SSH_KEY_PATH),
            '-N', '',  # No passphrase
            '-C', 'tunnel-manager-key'
        ], check=True, capture_output=True)
        
        SSH_KEY_PATH.chmod(0o600)
        print_success(f"SSH key generated: {SSH_KEY_PATH}")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to generate SSH key: {e}")
        cleanup_and_exit(1)


def remove_known_host(hostname: str):
    """Remove a host from the known hosts file"""
    if not KNOWN_HOSTS_FILE.exists():
        return
    
    try:
        subprocess.run([
            'ssh-keygen',
            '-f', str(KNOWN_HOSTS_FILE),
            '-R', hostname
        ], capture_output=True)
        print_info(f"Removed {hostname} from known hosts")
    except subprocess.CalledProcessError:
        pass


def test_ssh_connection(host: str, user: str, port: int = 22, password: Optional[str] = None, 
                       use_key: bool = False, timeout: int = 10) -> bool:
    """Test SSH connection to a host"""
    print_info(f"Testing connection to {user}@{host}:{port}...")
    
    ssh_opts = [
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', f'UserKnownHostsFile={KNOWN_HOSTS_FILE}',
        '-o', 'StrictHostKeyChecking=no',
        '-p', str(port)
    ]
    
    if use_key:
        ssh_opts.extend(['-o', 'BatchMode=yes', '-i', str(SSH_KEY_PATH)])
    
    cmd = ['ssh'] + ssh_opts + [f'{user}@{host}', 'exit']
    
    try:
        if password and not use_key:
            # Use sshpass for password authentication
            cmd = ['sshpass', '-e'] + cmd
            env = os.environ.copy()
            env['SSHPASS'] = password
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
        else:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        
        if result.returncode == 0:
            print_success(f"Connection to {host} successful")
            return True
        else:
            stderr = result.stderr.decode('utf-8', errors='ignore')
            
            # Handle host key changed error
            if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in stderr or 'Host key verification failed' in stderr:
                print_warning("Host key has changed. Removing old key...")
                remove_known_host(host)
                # Retry once
                return test_ssh_connection(host, user, port, password, use_key, timeout)
            
            print_error(f"Connection failed: {stderr.split('Â')[-1].strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print_error(f"Connection to {host} timed out (may be blocked by firewall)")
        return False
    except Exception as e:
        print_error(f"Connection test failed: {e}")
        return False


def get_healthy_ip(node_name: str, config_key: str, config: Dict, user: str, 
                   port: int = 22, password: Optional[str] = None) -> Tuple[str, str]:
    """Get a healthy IP for a node, either from config or by prompting user"""
    
    # Check if we have a saved IP
    if config_key in config:
        saved_ip = config[config_key]
        print_info(f"Testing saved IP for {node_name}: {saved_ip}")
        
        # First try with key
        if test_ssh_connection(saved_ip, user, port, use_key=True):
            return saved_ip, user
        
        # Try with password if provided
        if password and test_ssh_connection(saved_ip, user, port, password=password):
            return saved_ip, user
        
        print_warning(f"Saved IP {saved_ip} is no longer reachable")
        del config[config_key]
        save_config(config)
    
    # Prompt for new IP
    while True:
        print_info(f"\nConfiguration needed for: {node_name}")
        ip = get_user_input(f"Enter IP address for {node_name}", confirm=True)
        
        # Get password if not provided
        if not password:
            password = get_user_input(f"Enter password for {user}@{ip}", confirm=True, password=True)
            os.environ['SSH_TUNNEL_PASSWORD'] = password  # Store in memory
        
        # Test connection with password
        if test_ssh_connection(ip, user, port, password=password):
            config[config_key] = ip
            save_config(config)
            print_success(f"IP {ip} saved for {node_name}")
            return ip, user
        
        print_error("IP is unhealthy. Please enter a new IP.")


def copy_ssh_key(host: str, user: str, port: int, password: str):
    """Copy SSH public key to remote host"""
    print_info(f"Copying SSH key to {user}@{host}...")
    
    pub_key_path = f"{SSH_KEY_PATH}.pub"
    
    try:
        # Use sshpass with ssh-copy-id
        env = os.environ.copy()
        env['SSHPASS'] = password
        
        cmd = [
            'sshpass', '-e', 'ssh-copy-id',
            '-o', f'UserKnownHostsFile={KNOWN_HOSTS_FILE}',
            '-o', 'StrictHostKeyChecking=no',
            '-i', str(SSH_KEY_PATH),
            '-p', str(port),
            f'{user}@{host}'
        ]
        
        result = subprocess.run(cmd, capture_output=True, env=env, timeout=30)
        
        if result.returncode == 0 or 'already exist' in result.stderr.decode('utf-8', errors='ignore'):
            print_success(f"SSH key installed on {host}")
            return True
        else:
            print_error(f"Failed to copy key: {result.stderr.decode('utf-8', errors='ignore')}")
            return False
            
    except Exception as e:
        print_error(f"Failed to copy SSH key: {e}")
        return False


def execute_remote_command(host: str, user: str, command: str, port: int = 22, 
                          password: Optional[str] = None, timeout: int = 30) -> Tuple[bool, str]:
    """Execute a command on a remote host"""
    ssh_opts = [
        '-o', f'UserKnownHostsFile={KNOWN_HOSTS_FILE}',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-i', str(SSH_KEY_PATH),
        '-p', str(port)
    ]
    
    cmd = ['ssh'] + ssh_opts + [f'{user}@{host}', command]
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return result.returncode == 0, result.stdout.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def kill_process_on_port(host: str, user: str, port: int, remote_port: int):
    """Kill any process using the specified port on remote host"""
    print_info(f"Checking if port {remote_port} is in use on {host}...")
    
    # Find process using the port
    success, output = execute_remote_command(
        host, user,
        f"lsof -ti:{remote_port} || true",
        port=port
    )
    
    if success and output.strip():
        pid = output.strip()
        print_warning(f"Port {remote_port} is in use by PID {pid}. Killing process...")
        execute_remote_command(host, user, f"kill -9 {pid}", port=port)
        time.sleep(2)
        print_success(f"Process {pid} terminated")


def setup_reverse_tunnel(relay_host: str, relay_user: str, destination_host: str, 
                        destination_user: str, relay_password: str):
    """Set up reverse SSH tunnel from destination through relay"""
    print_banner(f"ESTABLISHING REVERSE TUNNEL", Colors.OKBLUE)
    
    # Kill any process using port 2222 on relay
    kill_process_on_port(relay_host, relay_user, 22, REVERSE_TUNNEL_PORT)
    
    # Create the reverse tunnel from destination to relay
    print_info(f"Creating reverse tunnel: {destination_host} -> {relay_host}:{REVERSE_TUNNEL_PORT}")
    
    ssh_opts = [
        '-N',  # No remote command
        '-f',  # Background
        '-o', f'UserKnownHostsFile={KNOWN_HOSTS_FILE}',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'ExitOnForwardFailure=yes',
        '-i', str(SSH_KEY_PATH),
        '-R', f'{REVERSE_TUNNEL_PORT}:localhost:22',
        f'{relay_user}@{relay_host}'
    ]
    
    # Execute tunnel from destination
    tunnel_cmd = ' '.join(['ssh'] + ssh_opts)
    success, output = execute_remote_command(
        destination_host, destination_user,
        tunnel_cmd,
        timeout=15
    )
    
    if not success:
        print_error(f"Failed to establish reverse tunnel: {output}")
        return False
    
    # Verify tunnel is working
    time.sleep(3)
    print_info("Verifying reverse tunnel...")
    
    test_cmd = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -p {REVERSE_TUNNEL_PORT} {destination_user}@localhost exit"
    success, output = execute_remote_command(relay_host, relay_user, test_cmd, timeout=10)
    
    if success:
        print_success("Reverse tunnel established and verified")
        return True
    else:
        print_error("Reverse tunnel verification failed")
        return False


def setup_socks_proxy(source_host: str, source_user: str, relay_host: str, relay_user: str):
    """Set up SOCKS5 proxy tunnel"""
    print_banner("ESTABLISHING SOCKS5 PROXY", Colors.OKBLUE)
    
    ssh_opts = [
        '-N',  # No remote command
        '-f',  # Background
        '-o', f'UserKnownHostsFile={KNOWN_HOSTS_FILE}',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-i', str(SSH_KEY_PATH),
        '-D', str(SOCKS_PROXY_PORT),
        f'{relay_user}@{relay_host}'
    ]
    
    tunnel_cmd = ' '.join(['ssh'] + ssh_opts)
    success, output = execute_remote_command(source_host, source_user, tunnel_cmd, timeout=15)
    
    if success:
        print_success(f"SOCKS5 proxy established on {source_host}:{SOCKS_PROXY_PORT}")
        print_info(f"To use the proxy on {source_host}, run:")
        print(f"{Colors.BOLD}export all_proxy=socks5h://127.0.0.1:{SOCKS_PROXY_PORT}{Colors.ENDC}")
        return True
    else:
        print_error(f"Failed to establish SOCKS5 proxy: {output}")
        return False


def generate_connection_commands(relay_host: str, relay_user: str, field_unit_user: str,
                                iran_server_host: str, iran_server_user: str):
    """Generate and display connection commands for the user"""
    print_banner("SETUP COMPLETE - CONNECTION COMMANDS", Colors.OKGREEN)
    
    print(f"{Colors.BOLD}=== Connect to Field Unit (Iran MacBook) ==={Colors.ENDC}")
    print(f"{Colors.OKCYAN}ssh -J {relay_user}@{relay_host}:22 -p {REVERSE_TUNNEL_PORT} {field_unit_user}@localhost -i {SSH_KEY_PATH} -o UserKnownHostsFile={KNOWN_HOSTS_FILE}{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}=== Connect to Iran Server (via Field Unit) ==={Colors.ENDC}")
    print(f"{Colors.OKCYAN}ssh -J {relay_user}@{relay_host}:22,{field_unit_user}@localhost:{REVERSE_TUNNEL_PORT} {iran_server_user}@{iran_server_host} -i {SSH_KEY_PATH} -o UserKnownHostsFile={KNOWN_HOSTS_FILE}{Colors.ENDC}\n")
    
    # Generate SSH config snippet
    print(f"{Colors.BOLD}=== Optional: Add to ~/.ssh/config for easy access ==={Colors.ENDC}")
    config_snippet = f"""
Host tunnel-relay
    HostName {relay_host}
    User {relay_user}
    IdentityFile {SSH_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host field-unit
    HostName localhost
    Port {REVERSE_TUNNEL_PORT}
    User {field_unit_user}
    ProxyJump tunnel-relay
    IdentityFile {SSH_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host iran-server
    HostName {iran_server_host}
    User {iran_server_user}
    ProxyJump tunnel-relay,field-unit
    IdentityFile {SSH_KEY_PATH}
    UserKnownHostsFile {KNOWN_HOSTS_FILE}
    ServerAliveInterval 30
    ServerAliveCountMax 3
"""
    print(f"{Colors.OKCYAN}{config_snippet}{Colors.ENDC}")
    print(f"{Colors.BOLD}After adding this config, simply use:{Colors.ENDC}")
    print(f"{Colors.OKGREEN}  ssh field-unit{Colors.ENDC}")
    print(f"{Colors.OKGREEN}  ssh iran-server{Colors.ENDC}\n")


def main():
    """Main execution flow"""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='Advanced Multi-Hop SSH Tunnel Manager')
    parser.add_argument('-u', '--unfiltered', action='store_true', 
                       help='Enable unfiltered mode (SOCKS5 proxy)')
    args = parser.parse_args()
    
    print_banner(f"SSH TUNNEL MANAGER v{VERSION}", Colors.HEADER)
    
    # Bootstrap dependencies
    if not bootstrap_dependencies():
        print_error("Dependency installation failed. Cannot continue.")
        cleanup_and_exit(1)
    
    # Check for updates
    new_version = check_for_updates()
    if new_version:
        prompt_update(new_version)
    
    # Load config
    config = load_config()
    
    # Prompt for config wipe
    prompt_wipe()
    
    # Generate SSH keys
    generate_ssh_key()
    
    # Node configuration
    print_banner("NODE CONFIGURATION", Colors.OKCYAN)
    
    # Get relay (Germany) credentials
    relay_user = get_user_input("Enter username for Germany Server (Relay)", confirm=False)
    relay_password = os.environ.get('SSH_TUNNEL_PASSWORD') or get_user_input(
        f"Enter password for {relay_user}@Germany", confirm=True, password=True
    )
    os.environ['SSH_TUNNEL_PASSWORD'] = relay_password
    
    relay_host, relay_user = get_healthy_ip(
        "Germany Server (Relay)", "relay_host", config, relay_user, 
        password=relay_password
    )
    
    # Copy key to relay
    copy_ssh_key(relay_host, relay_user, 22, relay_password)
    
    # Get field unit (Iran MacBook) credentials
    field_unit_user = get_user_input("Enter username for Iran Field Unit (MacBook)", confirm=False)
    field_unit_password = get_user_input(
        f"Enter password for {field_unit_user}@Field Unit", confirm=True, password=True
    )
    
    field_unit_host, field_unit_user = get_healthy_ip(
        "Iran Field Unit (MacBook)", "field_unit_host", config, field_unit_user,
        password=field_unit_password
    )
    
    # Copy key to field unit
    copy_ssh_key(field_unit_host, field_unit_user, 22, field_unit_password)
    
    # Generate key on relay and copy to field unit
    print_info("Setting up key-based auth from Relay to Field Unit...")
    execute_remote_command(
        relay_host, relay_user,
        "test -f ~/.ssh/id_rsa || ssh-keygen -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa"
    )
    
    # Get relay's public key
    success, relay_pubkey = execute_remote_command(relay_host, relay_user, "cat ~/.ssh/id_rsa.pub")
    if success and relay_pubkey:
        # Add to field unit's authorized_keys
        add_key_cmd = f"mkdir -p ~/.ssh && echo '{relay_pubkey.strip()}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        execute_remote_command(field_unit_host, field_unit_user, add_key_cmd)
        print_success("Relay can now access Field Unit via key")
    
    # Get Iran server credentials
    iran_server_user = get_user_input("Enter username for Iran Server", confirm=False)
    iran_server_password = get_user_input(
        f"Enter password for {iran_server_user}@Iran Server", confirm=True, password=True
    )
    
    iran_server_host, iran_server_user = get_healthy_ip(
        "Iran Server", "iran_server_host", config, iran_server_user,
        password=iran_server_password
    )
    
    # Copy key to Iran server
    copy_ssh_key(iran_server_host, iran_server_user, 22, iran_server_password)
    
    # Generate key on field unit and copy to Iran server
    print_info("Setting up key-based auth from Field Unit to Iran Server...")
    execute_remote_command(
        field_unit_host, field_unit_user,
        "test -f ~/.ssh/id_rsa || ssh-keygen -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa"
    )
    
    success, field_pubkey = execute_remote_command(field_unit_host, field_unit_user, "cat ~/.ssh/id_rsa.pub")
    if success and field_pubkey:
        add_key_cmd = f"mkdir -p ~/.ssh && echo '{field_pubkey.strip()}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        execute_remote_command(iran_server_host, iran_server_user, add_key_cmd)
        print_success("Field Unit can now access Iran Server via key")
    
    # Set up reverse tunnel
    if not setup_reverse_tunnel(relay_host, relay_user, field_unit_host, field_unit_user, relay_password):
        print_error("Failed to establish reverse tunnel. Exiting.")
        cleanup_and_exit(1)
    
    # Set up SOCKS proxy if requested
    if args.unfiltered:
        # Set up proxy from field unit to relay
        setup_socks_proxy(field_unit_host, field_unit_user, relay_host, relay_user)
        
        # Set up proxy from Iran server to relay (via field unit)
        # First, ensure Iran server can reach relay
        print_info("Setting up Iran Server -> Relay connectivity for SOCKS proxy...")
        
        # Generate key on Iran server
        execute_remote_command(
            iran_server_host, iran_server_user,
            "test -f ~/.ssh/id_rsa || ssh-keygen -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa"
        )
        
        # Get Iran server's public key and add to relay
        success, iran_pubkey = execute_remote_command(iran_server_host, iran_server_user, "cat ~/.ssh/id_rsa.pub")
        if success and iran_pubkey:
            add_key_cmd = f"mkdir -p ~/.ssh && echo '{iran_pubkey.strip()}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            execute_remote_command(relay_host, relay_user, add_key_cmd)
            print_success("Iran Server can now access Relay via key")
        
        # Test connectivity
        test_cmd = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes {relay_user}@{relay_host} exit"
        success, output = execute_remote_command(iran_server_host, iran_server_user, test_cmd, timeout=15)
        
        if success:
            setup_socks_proxy(iran_server_host, iran_server_user, relay_host, relay_user)
        else:
            print_warning("Iran Server cannot directly reach Relay. SOCKS proxy not available.")
    
    # Display connection commands
    generate_connection_commands(relay_host, relay_user, field_unit_user, 
                                iran_server_host, iran_server_user)
    
    print_success("Setup complete! Use the commands above to connect.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nOperation cancelled by user")
        cleanup_and_exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        cleanup_and_exit(1)

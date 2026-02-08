# Advanced Multi-Hop SSH Tunnel Manager

A robust, production-ready Python script for establishing and managing complex, multi-hop reverse SSH tunneling architectures through censored networks (e.g., Great Firewall of China, Iran's filtering system).

## 🎯 Overview

This tool automates the creation of resilient SSH tunnels from networks with heavy filtering restrictions, enabling seamless access to remote systems through relay servers.

### Architecture

```
┌─────────────────┐       ┌──────────────────┐       ┌─────────────────────┐
│   Node A (PC)   │       │  Node B (Relay)  │       │ Node C (Field Unit) │
│   USA Client    │◄─────►│ Germany Server   │◄──────│   Iran MacBook      │
│                 │       │  (Vultr VPS)     │ Rev   │  (Behind Firewall)  │
└─────────────────┘       └──────────────────┘ Tun   └─────────────────────┘
                                                              │
                                                              │ Direct
                                                              ▼
                                                    ┌─────────────────────┐
                                                    │ Node D (Dest Server)│
                                                    │    Iran Server 2    │
                                                    │  (Behind Firewall)  │
                                                    └─────────────────────┘
```

## ✨ Features

### Core Capabilities
- ✅ **Automatic Dependency Management**: Auto-installs Python packages and system tools
- ✅ **Self-Update Mechanism**: Checks for newer versions from GitHub/CDN
- ✅ **State Recovery**: Wipe and restart from scratch to recover from broken states
- ✅ **Health Checks**: Tests server reachability before attempting connections
- ✅ **Password Automation**: Uses `sshpass` to eliminate repetitive password entry
- ✅ **Key-Based Authentication**: Automatically generates and distributes SSH keys
- ✅ **Resilient Tunneling**: Keep-alive settings optimized for GFW/censorship scenarios
- ✅ **SOCKS5 Proxy Mode**: Unfiltered browsing via `-u` flag
- ✅ **Clean Error Handling**: User-friendly errors, auto-fixes for common SSH issues
- ✅ **Signal Trapping**: Graceful cleanup on Ctrl+C or termination

### Security Features
- 🔐 Sandboxed known_hosts file (doesn't pollute system SSH config)
- 🔐 Unique key naming (`id_rsa_tunneltool`)
- 🔐 Password stored only in memory, never written to disk
- 🔐 Auto-removal of changed host keys
- 🔐 Key-based auth enforced after initial setup

## 🚀 Quick Start

### One-Liner Deployment

```bash
curl -sL https://github.com/dazaiop853-afk/tunnel-tool/main/ssh_tunnel_manager.py | python3
```

**Note**: Replace `YOUR_USERNAME/YOUR_REPO` with your actual GitHub repository path.

### Alternative: Download and Run

```bash
# Download the script
curl -sL https://raw.githubusercontent.com/dazaiop853-afk/tunnel-tool/main/ssh_tunnel_manager.py -o ssh_tunnel_manager.py

# Make it executable
chmod +x ssh_tunnel_manager.py

# Run it
./ssh_tunnel_manager.py
```

## 📋 Prerequisites

### Minimum Requirements
- **OS**: Linux (Ubuntu/Debian) or macOS
- **Python**: Python 3.7+
- **Network**: Outbound SSH (port 22) access

### Auto-Installed Dependencies
The script will automatically install:
- **Python Packages**: `paramiko`
- **System Tools**: `sshpass` (via Homebrew on macOS, apt on Linux)

### Manual Prerequisites (if needed)
```bash
# macOS
brew install python3 openssh

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 openssh-client
```

## 🎮 Usage

### Basic Mode (Reverse Tunnel Only)

```bash
python3 ssh_tunnel_manager.py
```

**What it does:**
1. Checks dependencies and installs missing ones
2. Checks for script updates
3. Prompts for node credentials (Germany relay, Iran field unit, Iran server)
4. Tests server health
5. Sets up key-based authentication
6. Establishes reverse SSH tunnel from Iran field unit → Germany relay
7. Configures direct connection from field unit → Iran server
8. Displays connection commands

### Unfiltered Mode (SOCKS5 Proxy)

```bash
python3 ssh_tunnel_manager.py -u
```

**Additional features:**
- Sets up SOCKS5 proxy on Iran field unit (port 1080)
- Sets up SOCKS5 proxy on Iran server (if reachable)
- Allows unfiltered internet browsing from censored networks

**To use the proxy:**
```bash
# On the Iran field unit
export all_proxy=socks5h://127.0.0.1:1080
curl ifconfig.me  # Should show Germany server IP
```

## 📡 Connection Examples

After successful setup, the script displays connection commands:

### Connect to Field Unit (Iran MacBook)
```bash
ssh -J relay_user@germany_ip:22 -p 2222 field_user@localhost \
    -i ~/.ssh_tunnel_manager/id_rsa_tunneltool \
    -o UserKnownHostsFile=~/.ssh_tunnel_manager/known_hosts
```

### Connect to Iran Server (via Field Unit)
```bash
ssh -J relay_user@germany_ip:22,field_user@localhost:2222 \
    iran_user@iran_server_ip \
    -i ~/.ssh_tunnel_manager/id_rsa_tunneltool \
    -o UserKnownHostsFile=~/.ssh_tunnel_manager/known_hosts
```

### Using SSH Config (Recommended)

Add the generated config snippet to `~/.ssh/config`:

```ssh-config
Host tunnel-relay
    HostName <germany-ip>
    User <relay-user>
    IdentityFile ~/.ssh_tunnel_manager/id_rsa_tunneltool
    UserKnownHostsFile ~/.ssh_tunnel_manager/known_hosts
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host field-unit
    HostName localhost
    Port 2222
    User <field-user>
    ProxyJump tunnel-relay
    IdentityFile ~/.ssh_tunnel_manager/id_rsa_tunneltool
    UserKnownHostsFile ~/.ssh_tunnel_manager/known_hosts
    ServerAliveInterval 30
    ServerAliveCountMax 3

Host iran-server
    HostName <iran-server-ip>
    User <iran-server-user>
    ProxyJump tunnel-relay,field-unit
    IdentityFile ~/.ssh_tunnel_manager/id_rsa_tunneltool
    UserKnownHostsFile ~/.ssh_tunnel_manager/known_hosts
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Then simply use:
```bash
ssh field-unit
ssh iran-server
```

## 🔧 Configuration

### Config Files Location
All configuration is stored in `~/.ssh_tunnel_manager/`:
- `config.json` - Saved healthy IPs
- `known_hosts` - Sandboxed SSH known hosts
- `id_rsa_tunneltool` - Private key
- `id_rsa_tunneltool.pub` - Public key

### Wiping Configuration

To start fresh:
```bash
python3 ssh_tunnel_manager.py
# When prompted: "Do you wish to wipe all existing configs?"
# Answer: yes
```

This removes all config files but preserves SSH keys if they're still valid.

## 🛠️ Troubleshooting

### Common Issues

#### 1. Connection Timeout
```
ERROR: Connection to x.x.x.x timed out (may be blocked by firewall)
```
**Solution**: 
- Verify the IP is correct
- Check if SSH (port 22) is open on the server
- If in Iran/China, the IP may be blocked; try a different relay server

#### 2. Host Key Changed
```
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
```
**Solution**: The script auto-fixes this, but if it persists:
```bash
ssh-keygen -f ~/.ssh_tunnel_manager/known_hosts -R <hostname>
```

#### 3. Port 2222 Already in Use
```
ERROR: Port 2222 is in use by PID xxxx
```
**Solution**: The script auto-kills the process, but you can manually check:
```bash
# On the relay server
lsof -ti:2222  # Find PID
kill -9 <PID>
```

#### 4. sshpass Not Found
```
ERROR: Failed to install sshpass
```
**Solution**:
```bash
# macOS
brew install sshpass

# Ubuntu/Debian
sudo apt-get install sshpass
```

#### 5. Permission Denied (publickey)
**Solution**: Re-run the script and wipe config:
```bash
python3 ssh_tunnel_manager.py
# Answer 'yes' to wipe config
# Re-enter credentials
```

### Debug Mode

For detailed SSH debugging, manually test connections:
```bash
ssh -vvv -i ~/.ssh_tunnel_manager/id_rsa_tunneltool \
    -o UserKnownHostsFile=~/.ssh_tunnel_manager/known_hosts \
    user@host
```

## 🔒 Security Considerations

1. **Password Storage**: Passwords are stored in memory only (`os.environ`) and never written to disk
2. **Key Security**: Keys are stored with `0600` permissions
3. **Known Hosts**: Sandboxed to avoid conflicts with system SSH
4. **Unfiltered Mode**: Be aware that SOCKS proxy traffic can be detected by sophisticated DPI systems

### Best Practices for Censored Networks

1. **Use obfuscated SSH**: Consider `obfs4proxy` or similar
2. **Rotate Relay IPs**: Change relay servers periodically
3. **Keep Tunnels Idle**: Don't send high-bandwidth traffic through tunnels
4. **Use HTTPS**: Always use encrypted protocols over the tunnel

## 🌐 Network Architecture Details

### Reverse Tunnel Flow
```
USA PC → Germany Server:22 → [Tunnel Port 2222] → Iran Field Unit:22
```

### Key Distribution
1. USA PC → Germany Server (password → key)
2. Germany Server → Iran Field Unit (auto-generated key)
3. USA PC → Iran Field Unit (via tunnel)
4. Iran Field Unit → Iran Server (auto-generated key)

### Keep-Alive Settings
All connections use:
- `ServerAliveInterval 30` - Send keep-alive every 30 seconds
- `ServerAliveCountMax 3` - Disconnect after 3 failed keep-alives
- `ExitOnForwardFailure yes` - Exit if port forwarding fails

## 📊 Exit Codes

- `0` - Success
- `1` - Dependency installation failed or critical error

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly in a GFW/censored environment
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This tool is provided for legitimate use cases such as:
- Remote system administration
- Access to personal servers in censored regions
- Educational purposes

**Users are responsible for complying with local laws and regulations.**

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/YOUR_REPO/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/YOUR_REPO/discussions)

## 🙏 Acknowledgments

Built with resilience patterns learned from:
- OpenSSH documentation
- Anti-censorship research (Tor Project, Lantern)
- GFW bypass techniques

---

**Made with ❤️ for freedom of information**

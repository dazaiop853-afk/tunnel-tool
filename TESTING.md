# Testing Checklist

## Pre-Deployment Testing

### Environment Setup
- [ ] Fresh Ubuntu 22.04 VM
- [ ] Fresh macOS 13+ system
- [ ] Access to test servers (Germany, Iran equivalents)
- [ ] Python 3.7+ installed
- [ ] No prior SSH configuration

### Dependency Bootstrap Tests

#### Test 1: Fresh System (No Dependencies)
```bash
# Remove all dependencies
pip uninstall -y paramiko
brew uninstall sshpass  # macOS
sudo apt-get remove -y sshpass  # Linux

# Run script
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects missing paramiko
- ✅ Installs paramiko via pip
- ✅ Detects missing sshpass
- ✅ Prompts for sudo (Linux) or uses brew (macOS)
- ✅ Installs sshpass successfully
- ✅ Continues to main flow

#### Test 2: Partial Dependencies
```bash
# Install only paramiko
pip install paramiko

# Run script
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Skips paramiko installation
- ✅ Installs sshpass
- ✅ Continues to main flow

### Update Mechanism Tests

#### Test 3: Version Check (Same Version)
```bash
# Edit GITHUB_RAW_URL to point to test repo with same version
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Checks remote version
- ✅ Displays "You are running the latest version"
- ✅ Continues to main flow

#### Test 4: Version Check (New Version Available)
```bash
# Edit GITHUB_RAW_URL to point to test repo with newer version
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects newer version
- ✅ Displays update prompt with curl command
- ✅ Asks "Continue with current version?"
- ✅ Exits if user says "no"
- ✅ Continues if user says "yes"

#### Test 5: Update Check Failure
```bash
# Set GITHUB_RAW_URL to invalid URL
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Displays warning "Could not check for updates"
- ✅ Continues to main flow without blocking

### Configuration Management Tests

#### Test 6: First Run (No Config)
```bash
# Ensure ~/.ssh_tunnel_manager doesn't exist
rm -rf ~/.ssh_tunnel_manager

python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Creates ~/.ssh_tunnel_manager directory
- ✅ Does not prompt for config wipe
- ✅ Continues to main flow

#### Test 7: Subsequent Run (Config Exists)
```bash
# Run again with existing config
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects existing configuration
- ✅ Prompts "Do you wish to wipe all existing configs?"
- ✅ If yes: wipes config, preserves SSH keys
- ✅ If no: continues with existing config

#### Test 8: Config Wipe
```bash
# Run with existing config
python3 ssh_tunnel_manager.py
# Answer "yes" to wipe
```

**Expected:**
- ✅ Removes config.json
- ✅ Removes known_hosts
- ✅ Preserves id_rsa_tunneltool and id_rsa_tunneltool.pub
- ✅ Displays "Configuration file removed"

### SSH Key Generation Tests

#### Test 9: Generate New Keys
```bash
rm -rf ~/.ssh_tunnel_manager/id_rsa_tunneltool*
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Generates new SSH key pair
- ✅ Creates id_rsa_tunneltool (private key)
- ✅ Creates id_rsa_tunneltool.pub (public key)
- ✅ Sets correct permissions (0600)
- ✅ No passphrase required

#### Test 10: Reuse Existing Keys
```bash
# Run again with existing keys
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects existing SSH keys
- ✅ Displays "SSH key already exists"
- ✅ Skips key generation

### Connection Health Tests

#### Test 11: Healthy Server (Password Auth)
```bash
python3 ssh_tunnel_manager.py
# Enter valid credentials
```

**Expected:**
- ✅ Prompts for IP and username
- ✅ Prompts for password with confirmation
- ✅ Tests connection with password
- ✅ Displays "Connection successful"
- ✅ Saves IP to config.json
- ✅ Continues to next step

#### Test 12: Unhealthy Server (Timeout)
```bash
python3 ssh_tunnel_manager.py
# Enter unreachable IP (e.g., 192.0.2.1)
```

**Expected:**
- ✅ Attempts connection
- ✅ Times out after 10 seconds
- ✅ Displays "Connection timed out (may be blocked by firewall)"
- ✅ Prompts "IP unhealthy, please enter a new IP"
- ✅ Re-prompts for IP

#### Test 13: Healthy Server (Key Auth)
```bash
# Second run after keys are installed
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Reads saved IP from config
- ✅ Tests connection with BatchMode=yes
- ✅ Succeeds with key-based auth
- ✅ Skips password prompt
- ✅ Continues to next step

#### Test 14: Saved IP No Longer Valid
```bash
# Manually edit config.json to invalid IP
# Or shut down the server
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Reads saved IP
- ✅ Tests connection fails
- ✅ Removes IP from config
- ✅ Prompts for new IP

### Password Automation Tests

#### Test 15: Password Confirmation
```bash
python3 ssh_tunnel_manager.py
# Enter password, then answer "no" to confirmation
```

**Expected:**
- ✅ Prompts for password again
- ✅ Asks for confirmation again
- ✅ Continues only after confirmation

#### Test 16: Password Storage
```bash
python3 ssh_tunnel_manager.py
# Check that password is not in any file
find ~/.ssh_tunnel_manager -type f -exec grep -l 'password' {} \;
```

**Expected:**
- ✅ Password not found in any file
- ✅ Password only in environment variable

### SSH Key Distribution Tests

#### Test 17: Copy Key to Server
```bash
python3 ssh_tunnel_manager.py
# Fresh server with no keys
```

**Expected:**
- ✅ Copies public key using sshpass
- ✅ Adds key to ~/.ssh/authorized_keys on remote
- ✅ Displays "SSH key installed on [host]"
- ✅ Subsequent connections use key

#### Test 18: Key Already Exists
```bash
# Run again with key already on server
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects key already exists
- ✅ Displays success message
- ✅ Does not duplicate key in authorized_keys

#### Test 19: Cross-Node Key Generation
```bash
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Generates key on Germany server
- ✅ Copies to Field Unit
- ✅ Generates key on Field Unit
- ✅ Copies to Iran Server
- ✅ All nodes can communicate via keys

### Host Key Management Tests

#### Test 20: Host Key Changed
```bash
# Simulate server reinstall (generate new host key on server)
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects "REMOTE HOST IDENTIFICATION HAS CHANGED"
- ✅ Displays warning message
- ✅ Automatically removes old key
- ✅ Retries connection
- ✅ Accepts new key
- ✅ Connection succeeds

#### Test 21: Sandboxed Known Hosts
```bash
# Check system known_hosts is untouched
cat ~/.ssh/known_hosts
cat ~/.ssh_tunnel_manager/known_hosts
```

**Expected:**
- ✅ System known_hosts unchanged
- ✅ All tunnel hosts in sandboxed known_hosts
- ✅ No conflicts

### Reverse Tunnel Tests

#### Test 22: Port Conflict Detection
```bash
# On relay server, manually bind port 2222
nc -l 2222 &

# Run script
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects port 2222 in use
- ✅ Identifies PID
- ✅ Kills process
- ✅ Establishes tunnel

#### Test 23: Reverse Tunnel Establishment
```bash
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Creates reverse tunnel from Field Unit to Relay
- ✅ Port 2222 on Relay forwards to Field Unit:22
- ✅ Verifies tunnel with test connection
- ✅ Displays "Reverse tunnel established and verified"

#### Test 24: ExitOnForwardFailure
```bash
# Simulate port forwarding failure
# (manually hold port 2222 on relay after kill check)
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ SSH exits immediately if port forward fails
- ✅ Script detects failure
- ✅ Displays error message
- ✅ Does not hang

### SOCKS Proxy Tests

#### Test 25: Unfiltered Mode (Field Unit)
```bash
python3 ssh_tunnel_manager.py -u
```

**Expected:**
- ✅ Establishes reverse tunnel
- ✅ Creates SOCKS5 proxy on Field Unit:1080
- ✅ Displays proxy usage instructions
- ✅ Can access via: ssh field-unit "curl -x socks5h://127.0.0.1:1080 ifconfig.me"

#### Test 26: Unfiltered Mode (Iran Server)
```bash
python3 ssh_tunnel_manager.py -u
```

**Expected:**
- ✅ Generates key on Iran Server
- ✅ Copies to Relay
- ✅ Tests Iran Server → Relay connectivity
- ✅ If successful: creates SOCKS5 proxy
- ✅ If failed: displays warning, skips proxy

#### Test 27: SOCKS Proxy Functionality
```bash
# On Field Unit
export all_proxy=socks5h://127.0.0.1:1080
curl ifconfig.me
```

**Expected:**
- ✅ Returns Relay server IP
- ✅ Not Field Unit IP
- ✅ Traffic routed through Relay

### Signal Handling Tests

#### Test 28: SIGINT (Ctrl+C) During Dependency Install
```bash
python3 ssh_tunnel_manager.py
# Press Ctrl+C during pip install
```

**Expected:**
- ✅ Displays "Received termination signal"
- ✅ Cleans up child processes
- ✅ Exits gracefully
- ✅ No zombie processes

#### Test 29: SIGINT During Connection Test
```bash
python3 ssh_tunnel_manager.py
# Press Ctrl+C during SSH connection test
```

**Expected:**
- ✅ Terminates SSH process
- ✅ Displays cleanup message
- ✅ Exits gracefully

#### Test 30: SIGTERM
```bash
python3 ssh_tunnel_manager.py &
PID=$!
sleep 5
kill -TERM $PID
```

**Expected:**
- ✅ Handles SIGTERM
- ✅ Cleans up processes
- ✅ Exits with code 0

### Error Handling Tests

#### Test 31: Invalid Password
```bash
python3 ssh_tunnel_manager.py
# Enter wrong password
```

**Expected:**
- ✅ Displays "Connection failed"
- ✅ Does NOT display raw SSH error
- ✅ Prompts for new IP (marked unhealthy)

#### Test 32: Network Unreachable
```bash
python3 ssh_tunnel_manager.py
# Enter IP on unreachable network
```

**Expected:**
- ✅ Times out gracefully
- ✅ Displays user-friendly error
- ✅ Prompts for new IP

#### Test 33: Permission Denied
```bash
# On server, remove user's authorized_keys
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects permission denied
- ✅ Displays error
- ✅ Offers to re-copy keys

### Output and Usability Tests

#### Test 34: Connection Commands Display
```bash
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Displays banner "SETUP COMPLETE"
- ✅ Shows exact SSH command for Field Unit
- ✅ Shows exact SSH command for Iran Server
- ✅ Includes ProxyJump syntax
- ✅ Includes correct ports and keys

#### Test 35: SSH Config Generation
```bash
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Generates SSH config snippet
- ✅ Includes all three hosts
- ✅ Correct ProxyJump chains
- ✅ Includes keep-alive settings

#### Test 36: Color Output
```bash
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Errors in red
- ✅ Success in green
- ✅ Info in cyan
- ✅ Warnings in yellow
- ✅ Banners in appropriate colors

### Edge Cases

#### Test 37: Very Long Timeout
```bash
# Server that accepts connections but hangs
python3 ssh_tunnel_manager.py
# Enter IP of hanging server
```

**Expected:**
- ✅ Times out after 10 seconds
- ✅ Does not hang indefinitely
- ✅ Prompts for new IP

#### Test 38: Multiple Rapid Ctrl+C
```bash
python3 ssh_tunnel_manager.py
# Press Ctrl+C multiple times rapidly
```

**Expected:**
- ✅ Handles gracefully
- ✅ No stack traces
- ✅ Clean exit

#### Test 39: Disk Full (Config Write)
```bash
# Fill up disk (or make ~/.ssh_tunnel_manager read-only)
chmod 444 ~/.ssh_tunnel_manager
python3 ssh_tunnel_manager.py
```

**Expected:**
- ✅ Detects write failure
- ✅ Displays error
- ✅ Continues if possible or exits gracefully

#### Test 40: IPv6 Server
```bash
python3 ssh_tunnel_manager.py
# Enter IPv6 address (e.g., 2001:db8::1)
```

**Expected:**
- ✅ Accepts IPv6 address
- ✅ Tests connection correctly
- ✅ Establishes tunnel

## Integration Testing

### End-to-End Test

```bash
# Complete flow from USA PC
python3 ssh_tunnel_manager.py

# After setup, test connections
ssh -J relay_user@germany_ip:22 -p 2222 field_user@localhost \
    -i ~/.ssh_tunnel_manager/id_rsa_tunneltool \
    -o UserKnownHostsFile=~/.ssh_tunnel_manager/known_hosts

# Test Iran Server connection
ssh -J relay_user@germany_ip:22,field_user@localhost:2222 \
    iran_user@iran_server_ip \
    -i ~/.ssh_tunnel_manager/id_rsa_tunneltool \
    -o UserKnownHostsFile=~/.ssh_tunnel_manager/known_hosts

# Test with SSH config
# (After adding generated config to ~/.ssh/config)
ssh field-unit
ssh iran-server
```

**Expected:**
- ✅ All connections succeed
- ✅ No password prompts
- ✅ Can execute commands on remote servers
- ✅ Connections stay alive (keep-alive working)

### Performance Test

```bash
# Test tunnel throughput
ssh field-unit "dd if=/dev/zero bs=1M count=100" | pv > /dev/null

# Test latency
ssh field-unit "ping -c 10 8.8.8.8"
```

**Expected:**
- ✅ Reasonable throughput (>1MB/s)
- ✅ Low latency increase (<100ms)
- ✅ Stable connection

## Checklist Summary

### Pre-Deployment
- [ ] All dependency tests pass
- [ ] Update mechanism works
- [ ] Config management works
- [ ] SSH key generation/reuse works

### Connection Tests
- [ ] Health checks work
- [ ] Password automation works
- [ ] Key distribution works
- [ ] Host key management works

### Tunnel Tests
- [ ] Reverse tunnel establishes
- [ ] Port conflict resolution works
- [ ] SOCKS proxy works (if -u)

### Reliability Tests
- [ ] Signal handling works
- [ ] Error messages are clear
- [ ] No zombie processes
- [ ] Clean exits

### Usability Tests
- [ ] Output is readable
- [ ] Connection commands are correct
- [ ] SSH config generation works

### Edge Cases
- [ ] Timeouts handled
- [ ] Multiple Ctrl+C handled
- [ ] IPv6 works

### Integration
- [ ] End-to-end flow works
- [ ] Can connect through full chain
- [ ] Performance acceptable

---

**Once all tests pass, the script is ready for production deployment!**

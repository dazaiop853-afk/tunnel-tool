# Deployment Guide

## GitHub Setup

### 1. Create GitHub Repository

```bash
# Create a new repository on GitHub (via web interface or CLI)
gh repo create ssh-tunnel-manager --public --description "Advanced Multi-Hop SSH Tunnel Manager"

# Clone the repository
git clone https://github.com/YOUR_USERNAME/ssh-tunnel-manager.git
cd ssh-tunnel-manager
```

### 2. Add Files

```bash
# Copy the script and README
cp /path/to/ssh_tunnel_manager.py .
cp /path/to/README.md .

# Add to git
git add ssh_tunnel_manager.py README.md
git commit -m "Initial commit: SSH Tunnel Manager v1.0.0"
git push origin main
```

### 3. Verify Raw URL

The script should be accessible at:
```
https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py
```

Test it:
```bash
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py | head -n 20
```

## CDN Setup (jsDelivr)

jsDelivr automatically serves GitHub content via CDN.

### URL Format
```
https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@main/ssh_tunnel_manager.py
```

### Advantages
- **Faster**: Global CDN edge servers
- **Cached**: Reduced latency
- **Version Pinning**: Can pin to specific commits/tags

### Usage Examples

```bash
# Latest version (main branch)
curl -sL https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@main/ssh_tunnel_manager.py | python3

# Specific version (tag)
curl -sL https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@v1.0.0/ssh_tunnel_manager.py | python3

# Specific commit
curl -sL https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@abc123/ssh_tunnel_manager.py | python3
```

## Version Management

### Creating Releases

```bash
# Tag a version
git tag -a v1.0.0 -m "Release v1.0.0: Initial stable release"
git push origin v1.0.0

# Create release on GitHub
gh release create v1.0.0 --title "v1.0.0" --notes "Initial stable release"
```

### Update Workflow

1. **Make changes to script**
   ```bash
   # Edit ssh_tunnel_manager.py
   # Update VERSION variable
   VERSION = "1.1.0"
   ```

2. **Commit and push**
   ```bash
   git add ssh_tunnel_manager.py
   git commit -m "v1.1.0: Add new feature"
   git push origin main
   ```

3. **Tag release**
   ```bash
   git tag -a v1.1.0 -m "Release v1.1.0"
   git push origin v1.1.0
   ```

4. **Users auto-update**
   - Script checks `GITHUB_RAW_URL` for new version
   - Prompts user to rerun curl command
   - Gets latest version automatically

## Distribution Methods

### Method 1: Direct GitHub Raw (Recommended for Development)
```bash
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py | python3
```

**Pros:**
- Always latest
- No CDN caching delays

**Cons:**
- Slower from some regions
- May be blocked in censored countries

### Method 2: jsDelivr CDN (Recommended for Production)
```bash
curl -sL https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@main/ssh_tunnel_manager.py | python3
```

**Pros:**
- Fast global delivery
- Often not blocked
- Automatic caching

**Cons:**
- ~12 hour cache (may not get instant updates)

### Method 3: Short URL (User-Friendly)

Use a URL shortener for easier sharing:

```bash
# Using git.io (GitHub short URLs - deprecated but still works)
curl https://git.io/ -i -F "url=https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py" -F "code=ssh-tunnel"

# Result: https://git.io/ssh-tunnel
# Usage:
curl -sL https://git.io/ssh-tunnel | python3
```

**Alternative: Custom domain**
```bash
# Set up on your domain (e.g., tunnel.yourdomain.com)
curl -sL https://tunnel.yourdomain.com/install | python3
```

## Security Considerations

### Code Signing (Advanced)

For maximum security, sign the script:

```bash
# Generate GPG key (if not already done)
gpg --full-generate-key

# Sign the script
gpg --output ssh_tunnel_manager.py.sig --detach-sign ssh_tunnel_manager.py

# Users verify before running
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py -o ssh_tunnel_manager.py
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py.sig -o ssh_tunnel_manager.py.sig
gpg --verify ssh_tunnel_manager.py.sig ssh_tunnel_manager.py
python3 ssh_tunnel_manager.py
```

### Checksum Verification

Provide checksums for verification:

```bash
# Generate SHA256 checksum
sha256sum ssh_tunnel_manager.py > sha256sum.txt

# Add to repository
git add sha256sum.txt
git commit -m "Add checksum"
git push
```

**Usage:**
```bash
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/ssh_tunnel_manager.py -o ssh_tunnel_manager.py
curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/ssh-tunnel-manager/main/sha256sum.txt -o sha256sum.txt
sha256sum -c sha256sum.txt
python3 ssh_tunnel_manager.py
```

## CI/CD Pipeline (Optional)

### GitHub Actions for Automated Testing

Create `.github/workflows/test.yml`:

```yaml
name: Test SSH Tunnel Manager

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ['3.7', '3.8', '3.9', '3.10', '3.11']

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install paramiko
    
    - name: Syntax check
      run: python -m py_compile ssh_tunnel_manager.py
    
    - name: Test imports
      run: python -c "import ssh_tunnel_manager"
```

## Monitoring and Analytics

### Track Usage (Optional)

Add analytics to track how many people use the script:

```python
import requests

def track_usage():
    try:
        # Use a simple analytics endpoint (e.g., Google Analytics Measurement Protocol)
        requests.post(
            'https://www.google-analytics.com/collect',
            data={
                'v': '1',
                'tid': 'UA-XXXXX-Y',
                't': 'event',
                'ec': 'script',
                'ea': 'run',
                'el': VERSION
            },
            timeout=1
        )
    except:
        pass  # Silent fail - don't interrupt script
```

## Backup and Recovery

### Backup Strategy

```bash
# Create backup branch
git checkout -b backup-$(date +%Y%m%d)
git push origin backup-$(date +%Y%m%d)

# Archive releases
gh release list
gh release download v1.0.0 --dir backups/v1.0.0
```

### Recovery

```bash
# Rollback to previous version
git revert HEAD
git push origin main

# Or restore from tag
git checkout v1.0.0 ssh_tunnel_manager.py
git commit -m "Rollback to v1.0.0"
git push origin main
```

## Documentation Updates

### Keep README in Sync

When updating the script:
1. Update version in script: `VERSION = "1.x.x"`
2. Update README.md with new features
3. Update this DEPLOYMENT.md if deployment process changes
4. Commit all changes together

```bash
git add ssh_tunnel_manager.py README.md DEPLOYMENT.md
git commit -m "v1.x.x: Description of changes"
git push origin main
git tag -a v1.x.x -m "Release v1.x.x"
git push origin v1.x.x
```

## User Support

### Issue Templates

Create `.github/ISSUE_TEMPLATE/bug_report.md`:

```markdown
---
name: Bug Report
about: Report a bug
title: '[BUG] '
labels: bug
---

**Environment**
- OS: [e.g., Ubuntu 22.04, macOS 13.0]
- Python Version: [e.g., 3.10.5]
- Script Version: [e.g., v1.0.0]

**Describe the bug**
A clear description of what happened.

**Steps to reproduce**
1. Run command '...'
2. Enter '...'
3. See error

**Expected behavior**
What you expected to happen.

**Error output**
```
Paste error here
```

**Additional context**
Any other relevant information.
```

## Maintenance Schedule

### Regular Tasks

**Weekly:**
- Check issues and pull requests
- Monitor for security vulnerabilities in dependencies

**Monthly:**
- Review analytics (if implemented)
- Update dependencies
- Test on latest OS versions

**Quarterly:**
- Major feature releases
- Security audit
- Documentation review

## Conclusion

Your script is now:
- ✅ Hosted on GitHub
- ✅ Available via CDN (jsDelivr)
- ✅ Versioned and tagged
- ✅ Ready for one-liner deployment
- ✅ Auto-updates users to latest version

**Final one-liner (replace with your actual repo):**
```bash
curl -sL https://cdn.jsdelivr.net/gh/YOUR_USERNAME/ssh-tunnel-manager@main/ssh_tunnel_manager.py | python3
```

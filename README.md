# Higinx

<img width="877" height="568" alt="image" src="https://github.com/user-attachments/assets/c7192635-0291-4fa3-9913-e8b5dc02c600" />

**Higinx** is a modern man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This tool is based on [Evilginx](https://github.com/kgretzky/evilginx2), originally released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website. Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

Higinx is significantly updated from the community version of Evilginx to include the following feature additions.

## Features (v3.4.0)

### Crawlfence Bot Detection
Advanced bot and crawler detection system to protect phishing infrastructure from security scanners:
- **JA4 TLS Fingerprinting**: Generates JA4 signatures from TLS ClientHello packets to identify automated tools
- **Browser Telemetry**: Injects JavaScript on landing pages to detect automation (WebDriver, Puppeteer, Selenium, headless browsers)
- **Learning Mode**: Collect legitimate JA4 signatures before enabling blocking
- **Per-Phishlet Configuration**: Enable/disable crawlfence per phishlet via YAML
- **Terminal Commands**: `crawlfence`, `crawlfence ja4`, `crawlfence clear`
- **Anti-Fingerprinting JS Injection**: Telemetry script is randomized per-session to evade signature-based detection:
  - Variable names, property access order, and timing jitter are randomized on every injection
  - Send method randomly alternates between `fetch()` and `XMLHttpRequest`
  - Static junk code (`doNothing()`) replaced with randomly generated decoy functions
- **Randomized Telemetry Endpoints**: The callback URL is no longer a static `/cf/<session_id>` path — each session gets a unique endpoint that resembles a legitimate resource (e.g., `/assets/js/<hash>.js`, `/cdn-cgi/scripts/<hash>.js`), matched via O(1) map lookup instead of per-request regex compilation
- **Expanded Bot Indicators**: Telemetry now checks 13+ signals beyond basic automation flags:
  - `window.chrome` presence (missing in headless Chrome)
  - `navigator.connection` (missing in many automation frameworks)
  - `Notification.permission` (defaults to "denied" in headless)
  - `navigator.hardwareConcurrency` (0 in bots)
  - `navigator.deviceMemory` (absent in headless Chrome)
  - Canvas fingerprint hash (consistent across bot sessions)
  - `window.outerWidth/outerHeight` (0x0 in headless)

### Multiple Certificate Support
Flexible certificate management for complex deployments:
- Support multiple PEM certificate/key pairs via comma-separated `-cert` and `-key` flags
- Automatic hostname matching using CN and SANs from certificates
- Wildcard certificate matching (e.g., `*.example.com`)
- Custom certificates in developer mode

### Webhook Notifications
Real-time event notifications for integration with external systems:
- Session created, credentials captured, tokens captured, session complete events
- Feishu-compatible webhook format with `msg_type` and `content` fields
- Configure via `webhook` command

### Statistics & Export
Campaign analytics and data export capabilities:
- **Stats Command**: View campaign statistics and analytics per phishlet
- **Sessions Export**: Export captured sessions in multiple formats:
  - JSON format for programmatic access
  - CSV format for spreadsheet analysis
  - Cookies format for browser import

### Phishlet Generator (Netter)
Automated phishlet creation from HAR files:
- **HAR File Parsing**: Generate phishlets from browser-exported HTTP Archive files
- **Full Traffic Analysis**: Automatically extracts domains, cookies, POST requests, and authentication flows
- **Interactive Selection**: Guided prompts for selecting auth tokens and credentials
- **Login Detection**: Automatically identifies login endpoints that set authentication cookies
- **YAML Generation**: Produces valid phishlet configurations with proper formatting

**Usage:**
```
evilginx> netter generate ~/Downloads/login-session.har
```

**Prerequisites:**
1. Open Chrome DevTools (F12) → Network tab
2. Clear existing requests
3. Perform complete login flow on target site
4. Right-click in Network tab → "Save all as HAR with content"

**Features:**
- Strict validation ensures HAR contains required authentication data
- Interactive cookie selection with auth token detection
- Automatic credential field detection (username/password)
- Generated phishlets include helpful comments for manual refinement
- Option to save directly to phishlets directory

### CLI Enhancements
Improved terminal experience:
- **Shell Command**: Execute bash commands directly from the higinx CLI
- **Enhanced Autocomplete**: Better tab completion for sessions, lures, and phishlets
- **Verbose Help System**: Detailed help with examples for all commands
- **Tokyo Night Color Scheme**: Modern blue/magenta/cyan theme for banner and logs

### Security & OPSEC
- **Referrer Header Blocking**: Prevents domain name leakage via Referrer headers
- **Improved Statistics**: Per-phishlet stats now correctly count BodyTokens and HttpTokens

## Installation

### Prerequisites
- Go 1.22 or higher
- Root/Administrator privileges (for ports 53 and 443)

### Building from Source

**Linux/macOS:**
```bash
# Clone the repository
git clone https://github.com/yourusername/higinx.git
cd higinx

# Build the project
make build

# The binary will be in ./build/higinx
```

**Windows:**
```cmd
git clone https://github.com/yourusername/higinx.git
cd higinx
build.bat
```

### Running

```bash
# Run with default configuration
sudo ./build/higinx

# Run with custom paths
sudo ./build/higinx -p <phishlets_dir> -c <config_dir> -t <redirectors_dir>

# Developer mode (self-signed certificates)
sudo ./build/higinx -developer

# Developer mode with custom certificates
sudo ./build/higinx -developer -cert cert1.pem,cert2.pem -key key1.pem,key2.pem

# Enable debug logging
sudo ./build/higinx -debug
```

### Directory Structure
After first run, higinx creates:
- `~/.evilginx/config.yaml` - Main configuration
- `~/.evilginx/data.db` - Session database
- `~/.evilginx/blacklist.txt` - IP blacklist
- `~/.evilginx/crt/` - SSL certificates

## Help

### Getting Started
1. Set your server's external IP: `config ip <your-ip>`
2. Set your domain: `config domain <your-domain>`
3. Enable a phishlet: `phishlets enable <name>`
4. Create a lure: `lures create <phishlet>`
5. Get the phishing URL: `lures get-url <id>`

### Common Commands

| Command | Description |
|---------|-------------|
| `help` | Show all available commands |
| `help <command>` | Show detailed help for a command |
| `config` | View/modify configuration |
| `phishlets` | List all phishlets |
| `phishlets enable <name>` | Enable a phishlet |
| `phishlets disable <name>` | Disable a phishlet |
| `lures` | List all lures |
| `lures create <phishlet>` | Create a new lure |
| `lures get-url <id>` | Get phishing URL for a lure |
| `sessions` | List captured sessions |
| `sessions <id>` | View session details |
| `sessions export <format>` | Export sessions (json/csv/cookies) |
| `stats` | View campaign statistics |
| `webhook` | Configure webhook notifications |
| `crawlfence` | Manage bot detection |
| `shell <command>` | Execute a shell command |
| `blacklist` | Manage IP blacklist |
| `clear` | Clear the terminal |

### Phishlet Management
```
: phishlets                    # List all phishlets
: phishlets enable example     # Enable the example phishlet
: phishlets disable example    # Disable the example phishlet
: phishlets hostname example test.com  # Set hostname for phishlet
```

### Session Management
```
: sessions                     # List all sessions
: sessions 0                   # View details of session 0
: sessions delete 0            # Delete session 0
: sessions delete all          # Delete all sessions
: sessions export json         # Export sessions as JSON
: sessions export csv          # Export sessions as CSV
: sessions export cookies      # Export session cookies
```

### Crawlfence (Bot Detection)
```
: crawlfence                   # Show crawlfence status
: crawlfence enable example    # Enable for phishlet
: crawlfence disable example   # Disable for phishlet
: crawlfence ja4               # List learned JA4 signatures
: crawlfence clear             # Clear learned signatures
```

### Troubleshooting

**Port already in use:**
Ensure no other services are using ports 53 (DNS) or 443 (HTTPS).

**Certificate errors:**
- In production: Ensure your domain's DNS points to your server
- In developer mode: Use `-developer` flag for self-signed certs

**Sessions not capturing:**
- Verify phishlet is enabled: `phishlets`
- Check phishlet hostname is set correctly
- Ensure DNS is resolving to your server

## Roadmap
- [x] Support wildcard TLS certificates
- [x] Support loading multiple certificates from disk
- [x] Crawlfence initial implementation (Botguard)
- [x] Statistics and export initial implementation
- [x] Shell module
- [x] OPSEC improvements, obfuscation for inject_js, etc.
- [ ] Implement additional OPSEC hardening measures 
- [ ] Improve branding and aesthetics
- [ ] Add BiTB integration
- [ ] Add Rocketchat, SMS, etc. notifications
- [ ] Rewrite URLs on Phishing Pages to avoid detection through URL Path pattern matching
- [x] Define your own CSP (Content security Policy) to avoid telemetry/canary/detection by leaking phishing domains. Implement this PR: https://github.com/kgretzky/evilginx2/pull/1006/commits/d88b98c0d31ce662809797d0942bab101a18270d
- [x] Improve crawlfence JS injection and telemetry gathering
- [ ] Implement background browser
- [x] Revamp data storage
- [ ] Implement API and client-server architecture

### SQLite Migration (BuntDB Replacement)
The session database has been migrated from BuntDB to SQLite (via the pure-Go [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) driver, no CGO required):

- **Proper relational storage**: Sessions are stored in a typed schema with indexed columns instead of serialized JSON blobs in a key-value store
- **Efficient partial updates**: Updating a single field (e.g., username or password) writes only that column rather than re-serializing and replacing the entire session object
- **WAL mode**: Write-Ahead Logging provides better concurrent read/write performance and crash resilience
- **Maintained dependency**: BuntDB has been unmaintained since 2020; modernc.org/sqlite is actively developed and tracks upstream SQLite releases
- **Drop-in replacement**: The public `database.Database` API is completely unchanged — no modifications to any callers in `core/` or `main.go`
- **Same database path**: The SQLite file is created at the existing `~/.evilginx/data.db` location

### TLS ClientHello Parsing Enhancements
Extended the vendored `go-vhost` library to parse additional TLS ClientHello extensions required by Crawlfence JA4 fingerprinting:

- **supported_versions** (ext 43): Enables accurate TLS 1.3 version detection
- **ALPN** (ext 16): Extracts protocol negotiation values (h2, http/1.1)
- **signature_algorithms** (ext 13): Captures signature algorithm preferences
- **Extension type tracking**: All extension type IDs are now collected for JA4 extension count and hash computation

## Disclaimer

Higinx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

## License

**Higinx** is based on evilginx2 by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.

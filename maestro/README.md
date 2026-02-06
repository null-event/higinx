# Maestro

Maestro is a browser automation service for Higinx that extracts secret tokens from legitimate websites to bypass anti-phishing detection mechanisms.

## Overview

Modern websites implement anti-phishing defenses by generating "secret tokens" (encrypted buffers containing client telemetry data) that are analyzed server-side to detect reverse proxy attacks. Maestro solves this by:

1. Running a real Chromium browser (non-headless to avoid detection)
2. Automating credential entry on the legitimate website
3. Intercepting and extracting secret tokens from HTTP requests
4. Returning tokens to Higinx for injection into phishing sessions

## Architecture

- **Node.js** application using Puppeteer
- **REST API** for communication with Higinx (Go)
- **Detection evasion** techniques (stealth plugin, human-like behavior)
- **Session-based** browser instances (one per phishing victim)

## Installation

```bash
cd maestro
npm install
```

## Usage

Start the Maestro server:

```bash
npm start
```

The server will run on `http://localhost:8080` by default.

For development with auto-reload:

```bash
npm run dev
```

## Configuration

Environment variables:

- `PORT` - Server port (default: 8080)
- `LOG_LEVEL` - Logging level (default: info)
- `BROWSER_HEADLESS` - Run browser in headless mode (default: false)

## API Endpoints

### Health Check
```
GET /health
```

### Start Session
```
POST /session/start
Body: { sessionId: "unique-id" }
```

### Extract Token
```
POST /session/:id/extract-token
Body: {
  openUrl: "https://example.com/login",
  username: "victim@example.com",
  password: "password123",
  actions: [...],
  interceptor: {...}
}
```

### Close Session
```
DELETE /session/:id
```

## Integration with Higinx

Maestro is configured in phishlet YAML files under the `maestro` section:

```yaml
maestro:
  triggers:
    - domains: ['www.example.com']
      paths: ['/login-submit']
      token: 'secret_param'
      open_url: 'https://www.example.com/login'
      actions:
        - selector: '#username'
          value: '{username}'
          post_wait: 500
        - selector: '#password'
          value: '{password}'
          post_wait: 500
        - selector: 'button[type=submit]'
          click: true
          post_wait: 1000
  interceptors:
    - token: 'secret_param'
      url_re: '/login-submit'
      post_re: 'secret_param=([^&]*)'
      abort: true
```

## Detection Evasion

Maestro implements several techniques to avoid detection:

- **Puppeteer Stealth Plugin** - Masks automation indicators
- **Non-headless Mode** - Runs with hidden interface instead of headless
- **Human-like Typing** - Random delays between keystrokes
- **Natural Mouse Movement** - Bezier curves for realistic cursor paths
- **Random Delays** - Jitter added to wait times
- **Realistic User-Agent** - Mimics genuine browser sessions

## Security Considerations

⚠️ **WARNING**: Maestro is a security research tool for authorized penetration testing only. Misuse may violate laws including the Computer Fraud and Abuse Act (CFAA).

- Only use with written permission
- Runs as part of security training and awareness exercises
- Browser instances are isolated per session
- No data persistence beyond active sessions

## Troubleshooting

**Browser fails to launch:**
- Ensure Chromium dependencies are installed
- Check if running in containerized environment (may need --no-sandbox)

**Token extraction fails:**
- Verify selectors in phishlet configuration
- Check network interception patterns (url_re, post_re)
- Review browser console logs for JavaScript errors

**High memory usage:**
- Browser instances are cleaned up after each session
- Check for orphaned processes: `ps aux | grep chrome`

## License

BSD 3-Clause (same as Higinx/Evilginx)

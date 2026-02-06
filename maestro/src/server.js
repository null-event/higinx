const express = require('express');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const BrowserManager = require('./browser-manager');
const TokenExtractor = require('./token-extractor');

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Initialize Express app
const app = express();
app.use(express.json({ limit: '10mb' }));

// Initialize browser manager
const browserManager = new BrowserManager(logger);

// Store active sessions
const sessions = new Map();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeSessions: sessions.size,
    uptime: process.uptime()
  });
});

// Start a new browser session
app.post('/session/start', async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }

    if (sessions.has(sessionId)) {
      return res.status(409).json({ error: 'Session already exists' });
    }

    logger.info(`Starting session: ${sessionId}`);

    const browser = await browserManager.launchBrowser();
    const page = await browser.newPage();

    sessions.set(sessionId, {
      browser,
      page,
      createdAt: Date.now()
    });

    logger.info(`Session started: ${sessionId}`);

    res.json({
      sessionId,
      status: 'started'
    });
  } catch (error) {
    logger.error(`Failed to start session: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Extract token from a session
app.post('/session/:id/extract-token', async (req, res) => {
  try {
    const { id } = req.params;
    const { openUrl, username, password, actions, interceptor } = req.body;

    if (!sessions.has(id)) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (!openUrl || !actions || !interceptor) {
      return res.status(400).json({ error: 'openUrl, actions, and interceptor are required' });
    }

    logger.info(`Extracting token for session: ${id}`);

    const session = sessions.get(id);
    const extractor = new TokenExtractor(session.page, logger);

    const token = await extractor.extractToken({
      openUrl,
      username,
      password,
      actions,
      interceptor
    });

    if (!token) {
      logger.warn(`Token extraction failed for session: ${id}`);
      return res.status(404).json({ error: 'Token not found' });
    }

    logger.info(`Token extracted for session: ${id}`);

    res.json({
      sessionId: id,
      token,
      status: 'success'
    });
  } catch (error) {
    logger.error(`Token extraction failed: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Close a session
app.delete('/session/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (!sessions.has(id)) {
      return res.status(404).json({ error: 'Session not found' });
    }

    logger.info(`Closing session: ${id}`);

    const session = sessions.get(id);

    try {
      await session.page.close();
    } catch (e) {
      logger.warn(`Error closing page: ${e.message}`);
    }

    try {
      await session.browser.close();
    } catch (e) {
      logger.warn(`Error closing browser: ${e.message}`);
    }

    sessions.delete(id);

    logger.info(`Session closed: ${id}`);

    res.json({
      sessionId: id,
      status: 'closed'
    });
  } catch (error) {
    logger.error(`Failed to close session: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Cleanup old sessions (30 minutes)
setInterval(() => {
  const now = Date.now();
  const maxAge = 30 * 60 * 1000; // 30 minutes

  for (const [sessionId, session] of sessions.entries()) {
    if (now - session.createdAt > maxAge) {
      logger.info(`Cleaning up stale session: ${sessionId}`);

      session.page.close().catch(() => {});
      session.browser.close().catch(() => {});
      sessions.delete(sessionId);
    }
  }
}, 5 * 60 * 1000); // Check every 5 minutes

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, closing all sessions...');

  for (const [sessionId, session] of sessions.entries()) {
    try {
      await session.page.close();
      await session.browser.close();
    } catch (e) {
      logger.warn(`Error during shutdown: ${e.message}`);
    }
  }

  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, closing all sessions...');

  for (const [sessionId, session] of sessions.entries()) {
    try {
      await session.page.close();
      await session.browser.close();
    } catch (e) {
      logger.warn(`Error during shutdown: ${e.message}`);
    }
  }

  process.exit(0);
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  logger.info(`Maestro server listening on port ${PORT}`);
});

module.exports = app;

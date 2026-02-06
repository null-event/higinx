const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

// Add stealth plugin to avoid detection
puppeteer.use(StealthPlugin());

class BrowserManager {
  constructor(logger) {
    this.logger = logger;
  }

  /**
   * Launch a new Chromium browser instance
   * @returns {Promise<Browser>} Puppeteer browser instance
   */
  async launchBrowser() {
    try {
      this.logger.info('Launching Chromium browser...');

      // Generate random viewport size for uniqueness
      const viewportWidth = 1280 + Math.floor(Math.random() * 320); // 1280-1600
      const viewportHeight = 720 + Math.floor(Math.random() * 360); // 720-1080

      const browser = await puppeteer.launch({
        headless: false, // Run with visible UI (hidden by window manager)
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu',
          '--window-position=-2400,-2400', // Position off-screen
          `--window-size=${viewportWidth},${viewportHeight}`,
        ],
        defaultViewport: {
          width: viewportWidth,
          height: viewportHeight,
          deviceScaleFactor: 1,
          hasTouch: false,
          isLandscape: true,
          isMobile: false,
        },
        ignoreHTTPSErrors: true,
      });

      this.logger.info(`Browser launched with viewport ${viewportWidth}x${viewportHeight}`);

      return browser;
    } catch (error) {
      this.logger.error(`Failed to launch browser: ${error.message}`);
      throw error;
    }
  }

  /**
   * Configure page with additional detection evasion
   * @param {Page} page - Puppeteer page instance
   */
  async configurePage(page) {
    try {
      // Override navigator.webdriver property
      await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', {
          get: () => false,
        });
      });

      // Add realistic plugins
      await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'plugins', {
          get: () => [
            {
              0: { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
              description: 'Portable Document Format',
              filename: 'internal-pdf-viewer',
              length: 1,
              name: 'Chrome PDF Plugin',
            },
            {
              0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
              description: '',
              filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
              length: 1,
              name: 'Chrome PDF Viewer',
            },
            {
              0: { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
              1: { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' },
              description: '',
              filename: 'internal-nacl-plugin',
              length: 2,
              name: 'Native Client',
            },
          ],
        });
      });

      // Set realistic permissions
      await page.evaluateOnNewDocument(() => {
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
          parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        );
      });

      this.logger.info('Page configured with detection evasion');
    } catch (error) {
      this.logger.warn(`Error configuring page: ${error.message}`);
    }
  }
}

module.exports = BrowserManager;

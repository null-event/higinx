const Evasion = require('./evasion');

class TokenExtractor {
  constructor(page, logger) {
    this.page = page;
    this.logger = logger;
    this.evasion = new Evasion(page, logger);
  }

  /**
   * Extract token from target website
   * @param {Object} config - Extraction configuration
   * @param {string} config.openUrl - URL to navigate to
   * @param {string} config.username - Username to enter
   * @param {string} config.password - Password to enter
   * @param {Array} config.actions - Actions to perform
   * @param {Object} config.interceptor - Request interceptor config
   * @returns {Promise<string|null>} Extracted token or null
   */
  async extractToken(config) {
    const { openUrl, username, password, actions, interceptor } = config;
    let extractedToken = null;

    try {
      // Set up request interception
      await this.page.setRequestInterception(true);

      this.page.on('request', async (request) => {
        const url = request.url();
        const method = request.method();

        // Check if this request matches our interceptor pattern
        if (method === 'POST' && new RegExp(interceptor.url_re).test(url)) {
          this.logger.info(`Intercepted request: ${url}`);

          const postData = request.postData();
          if (postData) {
            this.logger.debug(`POST data: ${postData.substring(0, 200)}...`);

            // Extract token using regex
            const regex = new RegExp(interceptor.post_re);
            const match = postData.match(regex);

            if (match && match[1]) {
              extractedToken = decodeURIComponent(match[1]);
              this.logger.info(`Token extracted: ${extractedToken.substring(0, 50)}...`);
            }
          }

          // Abort request if configured
          if (interceptor.abort) {
            this.logger.debug('Aborting intercepted request');
            request.abort('aborted');
            return;
          }
        }

        // Continue all other requests
        request.continue();
      });

      // Navigate to target URL
      this.logger.info(`Navigating to: ${openUrl}`);
      await this.page.goto(openUrl, {
        waitUntil: 'networkidle2',
        timeout: 30000
      });

      this.logger.info('Page loaded, executing actions...');

      // Execute actions sequentially
      for (let i = 0; i < actions.length; i++) {
        const action = actions[i];
        this.logger.debug(`Action ${i + 1}/${actions.length}: ${JSON.stringify(action)}`);

        await this.executeAction(action, username, password);
      }

      // Wait a bit for any final network requests
      await this.evasion.randomDelay(1000, 2000);

      // Check if token was extracted
      if (extractedToken) {
        this.logger.info('Token extraction successful');
        return extractedToken;
      } else {
        this.logger.warn('No token found in intercepted requests');
        return null;
      }
    } catch (error) {
      this.logger.error(`Token extraction error: ${error.message}`);
      throw error;
    } finally {
      // Disable request interception
      await this.page.setRequestInterception(false);
      this.page.removeAllListeners('request');
    }
  }

  /**
   * Execute a single action
   * @param {Object} action - Action configuration
   * @param {string} username - Username for substitution
   * @param {string} password - Password for substitution
   */
  async executeAction(action, username, password) {
    const { selector, value, click, post_wait } = action;

    try {
      // Wait for element to be present
      await this.page.waitForSelector(selector, { timeout: 10000 });

      // Scroll element into view
      await this.page.evaluate((sel) => {
        const element = document.querySelector(sel);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, selector);

      // Small delay after scroll
      await this.evasion.randomDelay(300, 600);

      if (click) {
        // Click action with evasion
        await this.evasion.humanClick(selector);
        this.logger.debug(`Clicked: ${selector}`);
      } else if (value !== undefined) {
        // Type action with evasion
        let finalValue = value;

        // Substitute placeholders
        if (value === '{username}') {
          finalValue = username;
        } else if (value === '{password}') {
          finalValue = password;
        }

        await this.evasion.humanType(selector, finalValue);
        this.logger.debug(`Typed value into: ${selector}`);
      }

      // Post-action wait with jitter
      if (post_wait) {
        const jitter = Math.floor(Math.random() * 200) - 100; // ±100ms
        const delay = Math.max(0, post_wait + jitter);
        await this.evasion.delay(delay);
      }
    } catch (error) {
      this.logger.error(`Action failed for selector ${selector}: ${error.message}`);
      throw error;
    }
  }
}

module.exports = TokenExtractor;

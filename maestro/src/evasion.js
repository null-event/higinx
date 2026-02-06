/**
 * Detection evasion techniques for human-like browser automation
 */
class Evasion {
  constructor(page, logger) {
    this.page = page;
    this.logger = logger;
  }

  /**
   * Simple delay
   * @param {number} ms - Milliseconds to wait
   */
  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Random delay within a range
   * @param {number} min - Minimum milliseconds
   * @param {number} max - Maximum milliseconds
   */
  async randomDelay(min, max) {
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    return this.delay(delay);
  }

  /**
   * Human-like typing with random delays between keystrokes
   * @param {string} selector - CSS selector of input element
   * @param {string} text - Text to type
   */
  async humanType(selector, text) {
    try {
      // Click on the input first
      await this.page.click(selector);
      await this.randomDelay(100, 300);

      // Clear existing value
      await this.page.evaluate((sel) => {
        const element = document.querySelector(sel);
        if (element) {
          element.value = '';
        }
      }, selector);

      // Type each character with human-like delays
      for (const char of text) {
        await this.page.type(selector, char, {
          delay: this.getTypingDelay()
        });
      }

      this.logger.debug(`Human-typed ${text.length} characters`);
    } catch (error) {
      this.logger.error(`Human typing failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get random typing delay (faster for common keys, slower for complex)
   * @returns {number} Delay in milliseconds
   */
  getTypingDelay() {
    // Most people type at 40-80 WPM (words per minute)
    // Average word is 5 characters, so 200-400 CPM (chars per minute)
    // That's 3.3-6.6 chars per second, or 150-300ms per character
    const baseDelay = 100; // Minimum delay
    const randomFactor = Math.random() * 150; // 0-150ms random
    const occasional_pause = Math.random() < 0.1 ? Math.random() * 300 : 0; // 10% chance of pause

    return baseDelay + randomFactor + occasional_pause;
  }

  /**
   * Human-like click with mouse movement
   * @param {string} selector - CSS selector of element to click
   */
  async humanClick(selector) {
    try {
      // Get element bounding box
      const element = await this.page.$(selector);
      if (!element) {
        throw new Error(`Element not found: ${selector}`);
      }

      const box = await element.boundingBox();
      if (!box) {
        throw new Error(`Element has no bounding box: ${selector}`);
      }

      // Calculate random point within element
      const x = box.x + box.width * (0.3 + Math.random() * 0.4); // 30-70% across
      const y = box.y + box.height * (0.3 + Math.random() * 0.4); // 30-70% down

      // Get current mouse position (start from somewhere realistic)
      const currentX = box.x - 100 - Math.random() * 200;
      const currentY = box.y - 100 - Math.random() * 200;

      // Move mouse to target with bezier curve
      await this.moveMouse(currentX, currentY, x, y);

      // Small delay before click
      await this.randomDelay(50, 150);

      // Click
      await this.page.mouse.click(x, y);

      this.logger.debug(`Human-clicked at (${Math.round(x)}, ${Math.round(y)})`);
    } catch (error) {
      this.logger.error(`Human click failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Move mouse in a bezier curve (more human-like)
   * @param {number} startX - Start X coordinate
   * @param {number} startY - Start Y coordinate
   * @param {number} endX - End X coordinate
   * @param {number} endY - End Y coordinate
   */
  async moveMouse(startX, startY, endX, endY) {
    const steps = 20 + Math.floor(Math.random() * 10); // 20-30 steps
    const duration = 200 + Math.random() * 300; // 200-500ms total

    // Control points for bezier curve
    const cp1x = startX + (endX - startX) * (0.25 + Math.random() * 0.25);
    const cp1y = startY + (endY - startY) * (0.25 + Math.random() * 0.25);
    const cp2x = startX + (endX - startX) * (0.5 + Math.random() * 0.25);
    const cp2y = startY + (endY - startY) * (0.5 + Math.random() * 0.25);

    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const { x, y } = this.cubicBezier(
        startX, startY,
        cp1x, cp1y,
        cp2x, cp2y,
        endX, endY,
        t
      );

      await this.page.mouse.move(x, y);
      await this.delay(duration / steps);
    }
  }

  /**
   * Calculate point on cubic bezier curve
   * @param {number} x0 - Start X
   * @param {number} y0 - Start Y
   * @param {number} x1 - Control point 1 X
   * @param {number} y1 - Control point 1 Y
   * @param {number} x2 - Control point 2 X
   * @param {number} y2 - Control point 2 Y
   * @param {number} x3 - End X
   * @param {number} y3 - End Y
   * @param {number} t - Time (0-1)
   * @returns {Object} {x, y} coordinates
   */
  cubicBezier(x0, y0, x1, y1, x2, y2, x3, y3, t) {
    const u = 1 - t;
    const tt = t * t;
    const uu = u * u;
    const uuu = uu * u;
    const ttt = tt * t;

    const x = uuu * x0 + 3 * uu * t * x1 + 3 * u * tt * x2 + ttt * x3;
    const y = uuu * y0 + 3 * uu * t * y1 + 3 * u * tt * y2 + ttt * y3;

    return { x, y };
  }

  /**
   * Random scroll (adds to human-like behavior)
   * @param {number} amount - Pixels to scroll (positive = down, negative = up)
   */
  async randomScroll(amount) {
    const steps = 5 + Math.floor(Math.random() * 5);
    const stepAmount = amount / steps;

    for (let i = 0; i < steps; i++) {
      await this.page.evaluate((px) => {
        window.scrollBy(0, px);
      }, stepAmount);

      await this.randomDelay(50, 150);
    }
  }
}

module.exports = Evasion;

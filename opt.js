/**
 * Optimized Consent Management Platform
 * @version 1.0.0
 */

(() => {
  // Core state management
  const state = {
    scripts: new Map(),
    scriptIdCounter: 0,
    isLoading: false,
    observer: null,
    isInitialized: false,
    bannerType: null,
    country: null,
    initialBlockingEnabled: true,
    isDebugMode: false,
    retryCount: 0
  };

  // Configuration
  const CONFIG = {
    API: {
      BASE_URL: 'https://cb-server.web-8fb.workers.dev/api',
      ENDPOINTS: {
        VISITOR_TOKEN: '/visitor-token',
        DETECT_LOCATION: '/cmp/detect-location',
        CONSENT: '/cmp/consent',
        SCRIPT_CATEGORY: '/cmp/script-category'
      }
    },
    STORAGE_KEYS: {
      VISITOR_ID: 'visitorId',
      SESSION_TOKEN: 'visitorSessionToken',
      CONSENT_GIVEN: 'consent-given',
      PREFERENCES: 'consent-preferences',
      POLICY_VERSION: 'consent-policy-version',
      DEBUG_MODE: 'consent-debug-mode'
    },
    CATEGORIES: {
      NECESSARY: 'Necessary',
      MARKETING: 'Marketing',
      ANALYTICS: 'Analytics',
      PERSONALIZATION: 'Personalization'
    },
    POLICY_VERSION: '1.2',
    RETRY_DELAY: 2000,
    MAX_RETRIES: 3,
    DEBUG: {
      ENABLED: false,
      LOG_LEVEL: 'info'
    }
  };

  // Script patterns for categorization
  const SCRIPT_PATTERNS = [
    {
      pattern: /collect|plausible\.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview/i,
      category: CONFIG.CATEGORIES.ANALYTICS
    },
    {
      pattern: /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|matomo/i,
      category: CONFIG.CATEGORIES.MARKETING
    },
    {
      pattern: /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i,
      category: CONFIG.CATEGORIES.PERSONALIZATION
    }
  ];

  // Resource blocking patterns
  const SUSPICIOUS_RESOURCE_PATTERNS = [
    /google-analytics/,
    /googletagmanager/,
    /facebook/,
    /doubleclick/,
    /analytics/,
    /tracking/,
    /matomo/,
    /clarity/,
    /hotjar/,
    /pixel/,
    /plausible\.io/,
    /collect/,
    /zoho/,
    /metrics/,
    /stat/,
    /fbevents/,
    /linkedin/,
    /twitter/,
    /pinterest/,
    /tiktok/,
    /snap/,
    /reddit/,
    /quora/,
    /outbrain/,
    /taboola/,
    /sharethrough/,
    /optimizely/,
    /hubspot/,
    /marketo/,
    /pardot/,
    /salesforce/,
    /intercom/,
    /drift/,
    /zendesk/,
    /freshchat/,
    /tawk/,
    /livechat/
  ];

  function isSuspiciousResource(url) {
    return SUSPICIOUS_RESOURCE_PATTERNS.some(pattern => pattern.test(url));
  }

  // Initial request blocking
  function setupInitialBlocking() {
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      const url = args[0];
      if (state.initialBlockingEnabled && isSuspiciousResource(url)) {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return originalFetch.apply(this, args);
    };

    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      xhr.open = function(method, url) {
        if (state.initialBlockingEnabled && isSuspiciousResource(url)) {
          return;
        }
        return originalOpen.apply(xhr, arguments);
      };
      return xhr;
    };

    const originalImage = window.Image;
    const originalSetAttribute = Element.prototype.setAttribute;
    window.Image = function(...args) {
      const img = new originalImage(...args);
      img.setAttribute = function(name, value) {
        if (name === 'src' && state.initialBlockingEnabled && isSuspiciousResource(value)) {
          return;
        }
        return originalSetAttribute.apply(this, arguments);
      };
      return img;
    };
  }

  // Utility functions
  const Utils = {
    generateUUID() {
      return crypto.randomUUID();
    },

    getHostname() {
      return window.location.hostname.replace(/^www\./, '').split('.')[0];
    },

    async delay(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    },

    arrayBufferToBase64(buffer) {
      return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    },

    base64ToArrayBuffer(base64) {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    },

    isTokenExpired(token) {
      try {
        const [payloadBase64] = token.split('.');
        const payload = JSON.parse(atob(payloadBase64));
        return !payload.exp || payload.exp < Math.floor(Date.now() / 1000);
      } catch (error) {
        console.error('Error checking token expiration:', error);
        return true;
      }
    },

    debugLog(message, level = 'info', data = null) {
      if (!state.isDebugMode && !CONFIG.DEBUG.ENABLED) return;

      const timestamp = new Date().toISOString();
      const logMessage = `[ConsentManager][${timestamp}][${level.toUpperCase()}] ${message}`;

      switch (level.toLowerCase()) {
        case 'error':
          console.error(logMessage, data || '');
          break;
        case 'warn':
          console.warn(logMessage, data || '');
          break;
        case 'debug':
          console.debug(logMessage, data || '');
          break;
        default:
          console.log(logMessage, data || '');
      }

      // Store logs if in debug mode
      if (state.isDebugMode) {
        const logs = JSON.parse(localStorage.getItem('consent-debug-logs') || '[]');
        logs.push({ timestamp, level, message, data });
        localStorage.setItem('consent-debug-logs', JSON.stringify(logs.slice(-1000))); // Keep last 1000 logs
      }
    },

    async retryOperation(operation, maxRetries = CONFIG.MAX_RETRIES) {
      let lastError;
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          return await operation();
        } catch (error) {
          lastError = error;
          Utils.debugLog(
            `Operation failed (attempt ${attempt}/${maxRetries}): ${error.message}`,
            'warn',
            error
          );
          if (attempt < maxRetries) {
            await Utils.delay(CONFIG.RETRY_DELAY * attempt);
          }
        }
      }
      throw lastError;
    }
  };

  // Encryption utilities
  const CryptoManager = {
    async generateKey() {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      return { key, iv };
    },

    async importKey(rawKey, usages = ['encrypt', 'decrypt']) {
      return await crypto.subtle.importKey(
        'raw',
        rawKey,
        { name: 'AES-GCM' },
        false,
        usages
      );
    },

    async encrypt(data, key, iv) {
      const encoder = new TextEncoder();
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoder.encode(data)
      );
      return Utils.arrayBufferToBase64(encrypted);
    },

    async decrypt(encryptedData, key, iv) {
      const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encryptedBytes
      );
      return new TextDecoder().decode(decrypted);
    }
  };

  // Storage Manager
  const StorageManager = {
    get(key) {
      try {
        return localStorage.getItem(key);
      } catch (error) {
        console.error(`Storage read error: ${key}`, error);
        return null;
      }
    },

    set(key, value) {
      try {
        localStorage.setItem(key, value);
        return true;
      } catch (error) {
        console.error(`Storage write error: ${key}`, error);
        return false;
      }
    },

    async setEncrypted(key, value) {
      try {
        const { key: cryptoKey, iv } = await CryptoManager.generateKey();
        const encryptedData = await CryptoManager.encrypt(JSON.stringify(value), cryptoKey, iv);
        const keyData = await crypto.subtle.exportKey('raw', cryptoKey);

        return this.set(key, JSON.stringify({
          encryptedData,
          iv: Array.from(iv),
          key: Array.from(new Uint8Array(keyData))
        }));
      } catch (error) {
        console.error(`Encryption error: ${key}`, error);
        return false;
      }
    },

    async getEncrypted(key) {
      try {
        const data = this.get(key);
        if (!data) return null;

        const { encryptedData, iv, key: keyData } = JSON.parse(data);
        const cryptoKey = await CryptoManager.importKey(new Uint8Array(keyData));
        const decrypted = await CryptoManager.decrypt(
          encryptedData,
          cryptoKey,
          new Uint8Array(iv)
        );

        return JSON.parse(decrypted);
      } catch (error) {
        console.error(`Decryption error: ${key}`, error);
        return null;
      }
    }
  };

  // Script Manager
  class ScriptManager {
    constructor() {
      this.scripts = new Map();
      this.setupObserver();
    }

    setupObserver() {
      if (state.observer) return;

      state.observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node.tagName === 'SCRIPT' && 
                !node.hasAttribute('data-consentbit-id') && 
                node.type !== 'text/plain') {
              this.handleNewScript(node);
            }
          }
        }
      });

      state.observer.observe(document.documentElement, {
        childList: true,
        subtree: true
      });
    }

    async handleNewScript(script) {
      try {
        const category = this.detectCategory(script);
        if (!category) {
          Utils.debugLog(`Script not categorized: ${script.src || 'inline script'}`, 'debug');
          return;
        }

        Utils.debugLog(`Handling new script in category: ${category}`, 'debug', {
          src: script.src,
          type: script.type,
          category
        });

        const placeholder = this.createPlaceholder(script, category);
        if (placeholder && script.parentNode) {
          script.parentNode.replaceChild(placeholder, script);
          Utils.debugLog('Script replaced with placeholder', 'debug', { id: placeholder.getAttribute('data-consentbit-id') });
        }
      } catch (error) {
        Utils.debugLog('Error handling new script', 'error', error);
      }
    }

    detectCategory(script) {
      const content = script.src || script.textContent || '';
      return SCRIPT_PATTERNS.find(({ pattern }) => 
        pattern.test(content))?.category || null;
    }

    createPlaceholder(script, category) {
      const id = `script-${state.scriptIdCounter++}`;
      const placeholder = document.createElement('script');
      
      placeholder.type = 'text/plain';
      placeholder.setAttribute('data-consentbit-id', id);
      placeholder.setAttribute('data-category', category);

      const scriptInfo = {
        id,
        category,
        type: script.type || 'text/javascript',
        async: script.async,
        defer: script.defer,
        src: script.src,
        content: script.textContent,
        attributes: {}
      };

      Array.from(script.attributes).forEach(attr => {
        if (!['src', 'type', 'async', 'defer'].includes(attr.name)) {
          scriptInfo.attributes[attr.name] = attr.value;
          placeholder.setAttribute(`data-${attr.name}`, attr.value);
        }
      });

      this.scripts.set(id, scriptInfo);
      return placeholder;
    }

    async restoreScript(id, preferences) {
      try {
        const scriptInfo = this.scripts.get(id);
        if (!scriptInfo) {
          Utils.debugLog(`Script info not found for ID: ${id}`, 'warn');
          return;
        }

        Utils.debugLog(`Restoring script: ${id}`, 'debug', scriptInfo);

        const placeholder = document.querySelector(`[data-consentbit-id="${id}"]`);
        if (!placeholder) {
          Utils.debugLog(`Placeholder not found for script: ${id}`, 'warn');
          this.scripts.delete(id);
          return;
        }

        if (!preferences[scriptInfo.category.toLowerCase()]) {
          Utils.debugLog(`Script category not allowed: ${scriptInfo.category}`, 'debug');
          return;
        }

        const script = document.createElement('script');
        Object.assign(script, {
          type: scriptInfo.type,
          async: scriptInfo.async,
          defer: scriptInfo.defer
        });

        Object.entries(scriptInfo.attributes).forEach(([name, value]) => {
          script.setAttribute(name, value);
        });

        if (scriptInfo.src) {
          script.src = scriptInfo.src;
          script.onerror = (error) => {
            Utils.debugLog(`Error loading script: ${scriptInfo.src}`, 'error', error);
          };
          await this.handleSpecialScript(script, scriptInfo);
        } else {
          script.textContent = scriptInfo.content;
        }

        placeholder.parentNode?.replaceChild(script, placeholder);
        this.scripts.delete(id);
        Utils.debugLog(`Script restored successfully: ${id}`, 'debug');
      } catch (error) {
        Utils.debugLog(`Error restoring script: ${id}`, 'error', error);
      }
    }

    async handleSpecialScript(script, info, unblockAll = false) {
      const handlers = {
        'googletagmanager.com': () => {
          script.onload = () => {
            if (typeof gtag === 'function') {
              gtag('consent', 'update', {
                'analytics_storage': unblockAll ? 'granted' : 'denied',
                'ad_storage': unblockAll ? 'granted' : 'denied',
                'functionality_storage': 'granted',
                'personalization_storage': unblockAll ? 'granted' : 'denied',
                'security_storage': 'granted',
                'ad_user_data': unblockAll ? 'granted' : 'denied',
                'ad_personalization': unblockAll ? 'granted' : 'denied'
              });
            }
          };
        },
        'facebook.com': () => {
          script.onload = () => {
            if (typeof fbq === 'function') {
              fbq('consent', 'grant');
            }
          };
        },
        'clarity.ms': () => {
          window.clarity = window.clarity || function(...args) {
            (window.clarity.q = window.clarity.q || []).push(args);
          };
          window.clarity.consent = true;
        },
        'matomo.cloud': () => {
          script.onload = () => {
            if (typeof _paq !== 'undefined') {
              _paq.push(['setConsentGiven']);
              _paq.push(['trackPageView']);
            }
          };
        },
        'hs-scripts.com': () => {
          script.onload = () => {
            if (typeof _hsq !== 'undefined') {
              _hsq.push(['doNotTrack', { track: true }]);
            }
          };
        },
        'plausible.io': () => {
          script.setAttribute('data-consent-given', 'true');
        },
        'static.hotjar.com': () => {
          window.hj = window.hj || function(...args) { 
            (window.hj.q = window.hj.q || []).push(args); 
          };
          script.onload = () => {
            if (typeof hj === 'function') {
              hj('consent', 'granted');
            }
          };
        }
      };

      for (const [domain, handler] of Object.entries(handlers)) {
        if (info.src.includes(domain)) {
          handler();
          break;
        }
      }
    }

    async restoreAllowedScripts(preferences) {
      const promises = Array.from(this.scripts.keys())
        .map(id => this.restoreScript(id, preferences));
      await Promise.all(promises);
    }

    async unblockAllScripts() {
      console.log("Unblocking all scripts and tools...");
      
      try {
        // Disable initial blocking
        state.initialBlockingEnabled = false;

        // Process all scripts
        for (const [id, scriptInfo] of this.scripts.entries()) {
          const placeholder = document.querySelector(`[data-consentbit-id="${id}"]`);
          if (!placeholder) {
            this.scripts.delete(id);
            continue;
          }

          const script = document.createElement('script');
          Object.assign(script, {
            type: scriptInfo.type,
            async: scriptInfo.async,
            defer: scriptInfo.defer
          });

          // Restore attributes
          Object.entries(scriptInfo.attributes).forEach(([name, value]) => {
            script.setAttribute(name, value);
          });

          if (scriptInfo.src) {
            script.src = scriptInfo.src;
            await this.handleSpecialScript(script, scriptInfo, true); // true indicates unblock all
          } else {
            script.textContent = scriptInfo.content;
          }

          placeholder.parentNode?.replaceChild(script, placeholder);
          this.scripts.delete(id);
        }

        // Disconnect observer
        if (state.observer) {
          state.observer.disconnect();
          state.observer = null;
        }

        console.log("All scripts unblocked successfully");
      } catch (error) {
        console.error("Error unblocking scripts:", error);
      }
    }

    async blockAllScripts() {
      console.log("Blocking all non-essential scripts...");

      try {
        // Enable initial blocking
        state.initialBlockingEnabled = true;

        // Get all scripts in the document
        const scripts = document.querySelectorAll("script:not([type='text/plain']):not([data-consentbit-id])");
        
        for (const script of scripts) {
          const category = this.detectCategory(script);
          if (category && category !== CONFIG.CATEGORIES.NECESSARY) {
            const placeholder = this.createPlaceholder(script, category);
            if (placeholder && script.parentNode) {
              script.parentNode.replaceChild(placeholder, script);
            }
          }
        }

        // Ensure observer is running
        this.setupObserver();

        console.log("Successfully blocked all non-essential scripts");
      } catch (error) {
        console.error("Error blocking scripts:", error);
      }
    }
  }

  // Banner Manager
  class BannerManager {
    constructor() {
      this.banners = {
        main: document.getElementById('consent-banner'),
        ccpa: document.getElementById('initial-consent-banner'),
        preferences: document.getElementById('main-banner'),
        simple: document.getElementById('simple-consent-banner')
      };
      this.setupHandlers();
    }

    setupHandlers() {
      document.querySelectorAll('[data-consent="accept-all"]')
        .forEach(btn => btn.addEventListener('click', () => this.handleAcceptAll()));

      document.querySelectorAll('[data-consent="reject-all"]')
        .forEach(btn => btn.addEventListener('click', () => this.handleRejectAll()));

      document.querySelectorAll('[data-consent="save-preferences"]')
        .forEach(btn => btn.addEventListener('click', () => this.handleSavePreferences()));
    }

    show(bannerKey) {
      const banner = this.banners[bannerKey];
      if (banner) {
        banner.style.display = 'block';
        banner.classList.add('show-banner');
        banner.classList.remove('hidden');
      }
    }

    hide(bannerKey) {
      const banner = this.banners[bannerKey];
      if (banner) {
        banner.style.display = 'none';
        banner.classList.remove('show-banner');
        banner.classList.add('hidden');
      }
    }

    hideAll() {
      Object.keys(this.banners).forEach(key => this.hide(key));
    }

    async handleAcceptAll() {
      const preferences = {
        necessary: true,
        marketing: true,
        analytics: true,
        personalization: true,
        ccpa: {
          DoNotShare: false
        }
      };
      await ConsentManager.savePreferences(preferences);
      this.hideAll();
    }

    async handleRejectAll() {
      const preferences = {
        necessary: true,
        marketing: false,
        analytics: false,
        personalization: false,
        ccpa: {
          DoNotShare: true
        }
      };
      await ConsentManager.savePreferences(preferences);
      this.hideAll();
    }

    async handleSavePreferences() {
      const preferences = {
        necessary: true,
        marketing: document.getElementById('marketing-checkbox')?.checked || false,
        analytics: document.getElementById('analytics-checkbox')?.checked || false,
        personalization: document.getElementById('personalization-checkbox')?.checked || false,
        ccpa: {
          DoNotShare: document.getElementById('do-not-share-checkbox')?.checked || false
        }
      };
      await ConsentManager.savePreferences(preferences);
      this.hideAll();
    }

    async updatePreferenceForm(preferences) {
      console.log("Updating preference form with:", preferences);

      const checkboxes = {
        necessary: document.querySelector('[data-consent-id="necessary-checkbox"]'),
        marketing: document.querySelector('[data-consent-id="marketing-checkbox"]'),
        personalization: document.querySelector('[data-consent-id="personalization-checkbox"]'),
        analytics: document.querySelector('[data-consent-id="analytics-checkbox"]'),
        doNotShare: document.querySelector('[data-consent-id="do-not-share-checkbox"]')
      };

      // If no form elements found, log and return
      if (!Object.values(checkboxes).some(checkbox => checkbox)) {
        console.log("No form elements found, form might not be loaded yet");
        return;
      }

      // Update necessary checkbox (always checked and disabled)
      if (checkboxes.necessary) {
        checkboxes.necessary.checked = true;
        checkboxes.necessary.disabled = true;
      }

      // Update other checkboxes
      if (checkboxes.marketing) {
        checkboxes.marketing.checked = Boolean(preferences.marketing);
      }

      if (checkboxes.personalization) {
        checkboxes.personalization.checked = Boolean(preferences.personalization);
      }

      if (checkboxes.analytics) {
        checkboxes.analytics.checked = Boolean(preferences.analytics);
      }

      if (checkboxes.doNotShare) {
        checkboxes.doNotShare.checked = Boolean(preferences.ccpa?.DoNotShare);
      }

      console.log("Form updated with preferences:", {
        necessary: true,
        marketing: checkboxes.marketing?.checked,
        personalization: checkboxes.personalization?.checked,
        analytics: checkboxes.analytics?.checked,
        doNotShare: checkboxes.doNotShare?.checked
      });
    }
  }

  // Main Consent Manager
  class ConsentManager {
    constructor() {
      this.scriptManager = new ScriptManager();
      this.bannerManager = new BannerManager();
      setupInitialBlocking();
    }

    async initialize() {
      if (state.isInitialized) return;

      try {
        // Check for debug mode
        state.isDebugMode = localStorage.getItem(CONFIG.STORAGE_KEYS.DEBUG_MODE) === 'true';
        Utils.debugLog('Initializing ConsentManager', 'info', { debugMode: state.isDebugMode });

        const token = await Utils.retryOperation(() => this.getVisitorToken());
        if (!token) {
          Utils.debugLog('Failed to get visitor token after retries', 'error');
          return;
        }

        StorageManager.set(CONFIG.STORAGE_KEYS.SESSION_TOKEN, token);
        Utils.debugLog('Visitor token obtained and stored', 'debug');

        // Load and apply saved preferences first
        const preferences = await this.loadAndApplySavedPreferences();
        Utils.debugLog('Loaded saved preferences', 'debug', preferences);

        if (!preferences || !StorageManager.get(CONFIG.STORAGE_KEYS.CONSENT_GIVEN)) {
          await this.scriptManager.setupObserver();
          await Utils.retryOperation(() => this.detectLocation());
        }

        await this.loadStyles();
        Utils.debugLog('Styles loaded successfully', 'debug');

        if (StorageManager.get(CONFIG.STORAGE_KEYS.CONSENT_GIVEN) === 'true') {
          this.bannerManager.hideAll();
          Utils.debugLog('Consent already given, banner hidden', 'debug');
        }

        state.isInitialized = true;
        Utils.debugLog('ConsentManager initialized successfully', 'info');
      } catch (error) {
        Utils.debugLog('Initialization error', 'error', error);
        if (state.retryCount < CONFIG.MAX_RETRIES) {
          state.retryCount++;
          Utils.debugLog(`Retrying initialization (attempt ${state.retryCount})`, 'warn');
          await Utils.delay(CONFIG.RETRY_DELAY);
          return this.initialize();
        }
      }
    }

    async getVisitorToken() {
      try {
        const existingToken = StorageManager.get(CONFIG.STORAGE_KEYS.SESSION_TOKEN);
        if (existingToken && !Utils.isTokenExpired(existingToken)) {
          return existingToken;
        }

        const visitorId = StorageManager.get(CONFIG.STORAGE_KEYS.VISITOR_ID) || Utils.generateUUID();
        StorageManager.set(CONFIG.STORAGE_KEYS.VISITOR_ID, visitorId);

        const response = await fetch(`${CONFIG.API.BASE_URL}${CONFIG.API.ENDPOINTS.VISITOR_TOKEN}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            visitorId,
            userAgent: navigator.userAgent,
            siteName: Utils.getHostname()
          })
        });

        if (!response.ok) throw new Error(`Token request failed: ${response.status}`);

        const { token } = await response.json();
        return token;
      } catch (error) {
        console.error('Token retrieval error:', error);
        return null;
      }
    }

    async loadStyles() {
      const styles = [
        "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css",
        "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css"
      ];

      await Promise.all(styles.map(href => {
        return new Promise((resolve, reject) => {
          const link = document.createElement('link');
          Object.assign(link, {
            rel: 'stylesheet',
            type: 'text/css',
            href,
            onload: resolve,
            onerror: reject
          });
          document.head.appendChild(link);
        });
      }));
    }

    async detectLocation() {
      try {
        const token = StorageManager.get(CONFIG.STORAGE_KEYS.SESSION_TOKEN);
        if (!token) {
          console.error('No session token available for location detection');
          return null;
        }

        const siteName = Utils.getHostname();
        const response = await fetch(
          `${CONFIG.API.BASE_URL}${CONFIG.API.ENDPOINTS.DETECT_LOCATION}?siteName=${
            encodeURIComponent(siteName)
          }`,
          {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            }
          }
        );

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('Failed to detect location:', errorData);
          throw new Error('Location detection failed');
        }

        const data = await response.json();
        if (!data.bannerType) {
          console.error('Invalid banner type in response:', data);
          throw new Error('Invalid banner type data format');
        }

        state.bannerType = data.bannerType;
        state.country = data.country;

        // Show appropriate banner based on type
        if (state.bannerType === 'GDPR') {
          this.bannerManager.show('main');
          this.bannerManager.hide('ccpa');
        } else if (state.bannerType === 'CCPA') {
          this.bannerManager.show('ccpa');
          this.bannerManager.hide('main');
        } else {
          console.warn('Unknown banner type:', state.bannerType);
          this.bannerManager.show('main');
          this.bannerManager.hide('ccpa');
        }

        return data;
      } catch (error) {
        console.error('Location detection error:', error);
        // Fallback to main banner on error
        this.bannerManager.show('main');
        return null;
      }
    }

    static async savePreferences(preferences) {
      try {
        const visitorId = StorageManager.get(CONFIG.STORAGE_KEYS.VISITOR_ID);
        const timestamp = new Date().toISOString();
        const clientId = Utils.getHostname();

        // Generate encryption key and IV for visitor ID
        const { key: visitorKey, iv: visitorIv } = await CryptoManager.generateKey();
        const encryptedVisitorId = await CryptoManager.encrypt(visitorId, visitorKey, visitorIv);
        const visitorKeyData = await crypto.subtle.exportKey('raw', visitorKey);

        // Generate encryption key and IV for preferences
        const { key: prefKey, iv: prefIv } = await CryptoManager.generateKey();
        const encryptedPreferences = await CryptoManager.encrypt(
          JSON.stringify(preferences),
          prefKey,
          prefIv
        );
        const prefKeyData = await crypto.subtle.exportKey('raw', prefKey);

        // Build complete payload
        const payload = {
          clientId,
          encryptedVisitorId: {
            encryptedData: encryptedVisitorId,
            encryptionKey: {
              key: Utils.arrayBufferToBase64(visitorKeyData),
              iv: Array.from(visitorIv)
            }
          },
          preferences: {
            encryptedData: encryptedPreferences,
            encryptionKey: {
              key: Utils.arrayBufferToBase64(prefKeyData),
              iv: Array.from(prefIv)
            }
          },
          policyVersion: CONFIG.POLICY_VERSION,
          timestamp,
          country: state.country,
          bannerType: state.bannerType,
          metadata: {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screenResolution: `${window.screen.width}x${window.screen.height}`,
            colorDepth: window.screen.colorDepth,
            devicePixelRatio: window.devicePixelRatio,
            cookiesEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            timeZoneOffset: new Date().getTimezoneOffset()
          }
        };

        // Store locally
        await StorageManager.setEncrypted(CONFIG.STORAGE_KEYS.PREFERENCES, preferences);
        StorageManager.set(CONFIG.STORAGE_KEYS.CONSENT_GIVEN, 'true');
        StorageManager.set(CONFIG.STORAGE_KEYS.POLICY_VERSION, CONFIG.POLICY_VERSION);

        // Send to server
        const token = StorageManager.get(CONFIG.STORAGE_KEYS.SESSION_TOKEN);
        if (token) {
          const response = await fetch(`${CONFIG.API.BASE_URL}${CONFIG.API.ENDPOINTS.CONSENT}`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`,
              'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
          });

          if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('Failed to save consent preferences:', errorData);
            throw new Error('Failed to save consent preferences');
          }
        }

        // Restore allowed scripts
        await ConsentManager.instance.scriptManager.restoreAllowedScripts(preferences);
      } catch (error) {
        console.error('Error saving preferences:', error);
        throw error;
      }
    }

    async loadPreferences() {
      return await StorageManager.getEncrypted(CONFIG.STORAGE_KEYS.PREFERENCES);
    }

    async unblockAllCookiesAndTools() {
      try {
        const preferences = {
          necessary: true,
          marketing: true,
          analytics: true,
          personalization: true,
          ccpa: {
            DoNotShare: false
          }
        };

        await this.savePreferences(preferences);
        await this.scriptManager.unblockAllScripts();
        this.bannerManager.hideAll();
        
        return true;
      } catch (error) {
        console.error("Error in unblockAllCookiesAndTools:", error);
        return false;
      }
    }

    async loadAndApplySavedPreferences() {
      console.log("Loading and applying saved preferences...");
      
      if (state.isLoading) {
        console.log("State is already loading, skipping...");
        return;
      }
      
      state.isLoading = true;

      try {
        const consentGiven = StorageManager.get(CONFIG.STORAGE_KEYS.CONSENT_GIVEN);
        console.log("Consent given:", consentGiven);

        if (consentGiven === "true") {
          const preferences = await this.loadPreferences();
          console.log("Loaded preferences:", preferences);

          if (preferences) {
            // Update form
            await this.bannerManager.updatePreferenceForm(preferences);
            
            // Restore allowed scripts
            await this.scriptManager.restoreAllowedScripts(preferences);

            return preferences;
          }
        }

        // Default preferences if nothing was loaded
        const defaultPreferences = {
          necessary: true,
          marketing: false,
          analytics: false,
          personalization: false,
          ccpa: { 
            DoNotShare: false 
          }
        };

        await this.bannerManager.updatePreferenceForm(defaultPreferences);
        return defaultPreferences;

      } catch (error) {
        console.error("Error loading preferences:", error);
        return {
          necessary: true,
          marketing: false,
          analytics: false,
          personalization: false,
          ccpa: { 
            DoNotShare: false 
          }
        };
      } finally {
        state.isLoading = false;
      }
    }

    static get instance() {
      if (!this._instance) {
        this._instance = new ConsentManager();
      }
      return this._instance;
    }
  }

  // Initialize on DOM load
  document.addEventListener('DOMContentLoaded', () => {
    ConsentManager.instance.initialize();
  });

  // Export necessary functions to window
  Object.assign(window, {
    acceptAllCookies: () => ConsentManager.instance.bannerManager.handleAcceptAll(),
    blockAllCookies: () => ConsentManager.instance.bannerManager.handleRejectAll(),
    loadConsentStyles: () => ConsentManager.instance.loadStyles(),
    initializeConsent: () => ConsentManager.instance.initialize(),
    unblockAllCookiesAndTools: () => ConsentManager.instance.unblockAllCookiesAndTools(),
    updatePreferenceForm: (prefs) => ConsentManager.instance.bannerManager.updatePreferenceForm(prefs),
    loadAndApplySavedPreferences: () => ConsentManager.instance.loadAndApplySavedPreferences(),
    blockAllScripts: () => ConsentManager.instance.scriptManager.blockAllScripts(),
    setDebugMode: (enabled) => {
      state.isDebugMode = enabled;
      localStorage.setItem(CONFIG.STORAGE_KEYS.DEBUG_MODE, enabled);
      Utils.debugLog(`Debug mode ${enabled ? 'enabled' : 'disabled'}`, 'info');
    },
    getDebugLogs: () => {
      return JSON.parse(localStorage.getItem('consent-debug-logs') || '[]');
    }
  });
})(); 

(async function () {
  const existing_Scripts = {};
  let scriptIdCounter = 0;
  let isLoadingState = false;
  let consentState = {};
  let observer;
  let currentBannerType = null;
  let country = null;
  let categorizedScripts = null;

  const suspiciousPatterns = [
    {
      pattern: /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview|amplitude|amplitude.com/i,
      category: "Analytics"
    },
    {
      pattern: /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|matomo/i,
      category: "Marketing"
    },
    {
      pattern: /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i,
      category: "Personalization"
    }
  ];

  /**
ENCRYPTION AND DECYPTION STARTS
*/
  const EncryptionUtils = {
    /**
     * Generates a new encryption key and IV
     * @returns {Promise<{key: CryptoKey, iv: Uint8Array}>}
     */
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
      const encodedData = encoder.encode(data);
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encodedData
      );
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
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



  function isTokenExpired(token) {

    const [payloadBase64] = token.split('.');
    const payload = JSON.parse(atob(payloadBase64));

    if (!payload.exp) return true;

    return payload.exp < Math.floor(Date.now() / 1000);

  }

  // Function to clean hostname
  async function cleanHostname(hostname) {
    let cleaned = hostname.replace(/^www\./, '');
    cleaned = cleaned.split('.')[0];
    return cleaned;
  }

  // Function to generate or get visitor ID
  async function getOrCreateVisitorId() {
    let visitorId = localStorage.getItem('visitorId');
    if (!visitorId) {
      visitorId = crypto.randomUUID();
      localStorage.setItem('visitorId', visitorId);
    }
    return visitorId;
  }

  async function detectLocationAndGetBannerType() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
        return null;
      }

      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      const response = await fetch(`https://cb-server.web-8fb.workers.dev/api/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      // Changed to check for bannerType instead of scripts
      if (!data.bannerType) {
        return null;
      }
      country = data.country;
      return data;
    } catch (error) {

      return null;
    }
  }

  function getClientIdentifier() {
    return window.location.hostname; // Use hostname as the unique client identifier
  }

  async function reblockDisallowedScripts(consentState) {

    const allScripts = document.querySelectorAll("script[data-category]");

    allScripts.forEach(script => {
      const categoriesAttr = script.getAttribute("data-category");
      if (!categoriesAttr) return;

      const categories = categoriesAttr.split(",").map(c => c.trim());
      const shouldBlock = categories.some(category => {
        const key = category.charAt(0).toUpperCase() + category.slice(1);
        return consentState[key] === false;
      });

      if (shouldBlock) {
        // External script
        if (script.src && !script.hasAttribute("data-original-src")) {
          const originalSrc = script.src;

          // Prevent duplicate by checking if another script already blocked it
          const alreadyBlocked = document.querySelector(`script[data-original-src="${originalSrc}"]`);
          if (alreadyBlocked) return;

          script.setAttribute("data-original-src", originalSrc);
          script.removeAttribute("src");

          blockedScripts.push({
            async: script.async,
            defer: script.defer,
            type: script.type,
            category: categories,
            src: originalSrc,
          });

        }

        // Inline script
        else if (!script.src && script.textContent && !script.hasAttribute("data-blocked-inline")) {
          const placeholder = createPlaceholder(script, categoriesAttr);
          if (placeholder) {
            script.parentNode.replaceChild(placeholder, script);
            existing_Scripts.push(placeholder);
          }
        }
      }
    });
  }


  /*BANNER */

  async function attachBannerHandlers() {
    const qs = (selector) => document.querySelector(selector);
    const qid = (id) => document.getElementById(id);

    const elements = {
      banners: {
        consent: qid("consent-banner"),
        ccpa: qid("initial-consent-banner"),
        main: qid("main-banner"),
        mainConsent: qid("main-consent-banner"),
        simple: qid("simple-consent-banner"),
      },
      buttons: {
        simpleAccept: qid("simple-accept"),
        simpleReject: qid("simple-reject"),
        toggleConsent: qid("toggle-consent-btn"),
        newToggleConsent: qid("new-toggle-consent-btn"),
        accept: qid("accept-btn"),
        decline: qid("decline-btn"),
        preferences: qid("preferences-btn"),
        savePreferences: qid("save-preferences-btn"),
        saveCCPA: qid("save-btn"),
        cancel: qid("cancel-btn"),
        close: qid("close-consent-banner"),
        doNotShareLink: qid("do-not-share-link"),
      },
      checkboxes: {
        necessary: qs('[data-consent-id="necessary-checkbox"]'),
        marketing: qs('[data-consent-id="marketing-checkbox"]'),
        personalization: qs('[data-consent-id="personalization-checkbox"]'),
        analytics: qs('[data-consent-id="analytics-checkbox"]'),
        doNotShare: qs('[data-consent-id="do-not-share-checkbox"]'),
      }
    };

    const { banners, buttons, checkboxes } = elements;

    if (checkboxes.necessary) {
      checkboxes.necessary.checked = true;
      checkboxes.necessary.disabled = true;
    }

    const buildPreferences = ({ marketing = false, personalization = false, analytics = false, doNotShare = false }) => ({
      Necessary: true,
      Marketing: marketing,
      Personalization: personalization,
      Analytics: analytics,
      ccpa: { DoNotShare: doNotShare }
    });

    const setupClick = (btn, fn) => btn?.addEventListener("click", fn);

    initializeBannerVisibility();

    // Handlers
    setupClick(buttons.simpleAccept, async (e) => {
      e.preventDefault();
      const prefs = buildPreferences({ marketing: true, personalization: true, analytics: true });
      await saveConsentState(prefs);
      await restoreAllowedScripts(prefs);
      hideBanner(banners.simple);
      localStorage.setItem("consent-given", "true");
    });

    setupClick(buttons.simpleReject, async (e) => {
      e.preventDefault();
      const prefs = buildPreferences();
      await saveConsentState(prefs);
      checkAndBlockNewScripts();
      hideBanner(banners.simple);
      localStorage.setItem("consent-given", "true");
    });

    const toggleBanner = () => {
      if (currentBannerType === 'CCPA') {
        showBanner(banners.ccpa);
        hideBanner(banners.consent);
      } else {
        showBanner(banners.consent);
        hideBanner(banners.ccpa);
      }
    };

    setupClick(buttons.toggleConsent, (e) => {
      e.preventDefault();
      toggleBanner();
    });

    setupClick(buttons.newToggleConsent, (e) => {
      e.preventDefault();
      toggleBanner();
    });

    setupClick(buttons.doNotShareLink, (e) => {
      e.preventDefault();
      hideBanner(banners.ccpa);
      showBanner(banners.mainConsent);
    });

    setupClick(buttons.close, (e) => {
      e.preventDefault();
      hideBanner(banners.mainConsent);
    });

    setupClick(buttons.accept, async (e) => {
      e.preventDefault();
      const prefs = buildPreferences({ marketing: true, personalization: true, analytics: true });
      await saveConsentState(prefs);
      await acceptAllCookies();
      hideBanner(banners.consent);
      hideBanner(banners.main);
    });

    setupClick(buttons.decline, async (e) => {
      e.preventDefault();
      const prefs = buildPreferences();
      await saveConsentState(prefs);
      await blockAllCookies();
      hideBanner(banners.consent);
      hideBanner(banners.main);
    });

    setupClick(buttons.preferences, (e) => {
      e.preventDefault();
      hideBanner(banners.consent);
      showBanner(banners.main);
    });

    setupClick(buttons.savePreferences, async (e) => {
      e.preventDefault();
      const prefs = buildPreferences({
        marketing: checkboxes.marketing?.checked,
        personalization: checkboxes.personalization?.checked,
        analytics: checkboxes.analytics?.checked
      });
      try {
        await saveConsentState(prefs);
        await restoreAllowedScripts(prefs);
      } catch { }
      hideBanner(banners.consent);
      hideBanner(banners.main);
    });

    setupClick(buttons.saveCCPA, async (e) => {
      e.preventDefault();
      const doNotShare = checkboxes.doNotShare?.checked || false;
      const prefs = buildPreferences({
        marketing: !doNotShare,
        personalization: !doNotShare,
        analytics: !doNotShare,
        doNotShare
      });

      if (doNotShare) {
        await blockAllCookies();
        await saveConsentState(prefs);
      } else {
        await unblockAllCookiesAndTools();
      }

      hideBanner(banners.ccpa);
      hideBanner(banners.mainConsent);
    });

    setupClick(buttons.cancel, (e) => {
      e.preventDefault();
      ["marketing", "personalization", "analytics"].forEach((key) => {
        if (checkboxes[key]) checkboxes[key].checked = false;
      });

      const prefs = buildPreferences({ doNotShare: true });
      saveConsentState(prefs);
      reblockDisallowedScripts(prefs);
      localStorage.setItem("consent-given", "true");
      hideBanner(banners.consent);
      hideBanner(banners.main);
    });
  }



  async function initializeBannerVisibility() {
    const locationData = await detectLocationAndGetBannerType();
    currentBannerType = locationData?.bannerType;
    country = locationData?.country;
    const consentGiven = localStorage.getItem("consent-given");
    const consentBanner = document.getElementById("consent-banner"); // GDPR banner
    const ccpaBanner = document.getElementById("initial-consent-banner"); // CCPA banner
    const mainConsentBanner = document.getElementById("main-consent-banner");

    if (consentGiven === "true") {
      hideBanner(consentBanner);
      hideBanner(ccpaBanner);
      return;
    }
    // Show the appropriate banner based on location
    if (currentBannerType === "CCPA") {
      showBanner(ccpaBanner); // Show CCPA banner
      hideBanner(consentBanner); // Hide GDPR banner
      hideBanner(mainConsentBanner);
    } else {
      showBanner(consentBanner); // Default to showing GDPR banner
      hideBanner(ccpaBanner);
    }
  }


  function initializeBanner() {


    // Wait for DOM to be fully loaded
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', attachBannerHandlers);
    } else {
      attachBannerHandlers();
    }
  }

  function showBanner(banner) {
    if (banner) {
      banner.style.display = "block";
      banner.classList.add("show-banner");
      banner.classList.remove("hidden");
    }
  }

  function hideBanner(banner) {
    if (banner) {
      banner.style.display = "none";
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }


  /*BANNER ENDS*/

  /*CONSENT STATE*/




  /*CONSENT  SAVING TO LOCALSTORAGE STARTS*/
  // Fetches ONLY cookie expiration - WARNING: NOT RECOMMENDED for ccpa.js.
  // Fetches ONLY cookie expiration - WARNING: NOT RECOMMENDED for this script.
  // Expiration duration should ideally be injected by the backend using site owner context.
  async function fetchCookieExpirationDays() {

    const sessionToken = localStorage.getItem("visitorSessionToken");

    if (!sessionToken) {
      console.warn("fetchCookieExpirationDays: No visitor session token found.");
      return "180";
    }

    try {

      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/app-data?siteName=${encodeURIComponent(siteName)}`;

      const response = await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${sessionToken}`,
          "Accept": "application/json"
        }
      });

      if (!response.ok) {       
        return "180";
      }

      // Expect backend to return { cookieExpiration: "..." or null }
      const data = await response.json();

      // Check if the expected property exists and is not null
      if (data && data.cookieExpiration !== null && data.cookieExpiration !== undefined) {
        console.log("fetchCookieExpirationDays: Received expiration value:", data.cookieExpiration);
        // Return the value (should be string or null based on backend)
        return String(data.cookieExpiration);
      } else {
        console.warn("fetchCookieExpirationDays: 'cookieExpiration' was null or missing in response.", data);
        // Fallback if value is explicitly null or missing
        return null; // Or return default like "180"
      }

    } catch (error) {
      console.error("fetchCookieExpirationDays: Network or parsing error:", error);
      // Fallback on network/fetch error
      return null; // Or return default like "180" on error
    }
  }


  async function saveConsentState(preferences) {
    const clientId = getClientIdentifier();
    const visitorId = localStorage.getItem("visitorId");
    const policyVersion = "1.2";
    const timestamp = new Date().toISOString();
    const sessionToken = localStorage.getItem("visitorSessionToken");
    const CONSENTBIT_CCPA_CONFIG = {
      cookieExpirationDays: 180
    };
  
    if (!sessionToken) return;
  
    const savedAtTimestamp = Date.now();
    let expiresAtTimestamp = null;
    let expirationDurationDays = null;
  
    try {
      const fetchedExpirationStr = await fetchCookieExpirationDays();
      const expirationDaysStr = fetchedExpirationStr ?? CONSENTBIT_CCPA_CONFIG.cookieExpirationDays.toString();
      const expirationDays = parseInt(expirationDaysStr, 10);
  
      if (!isNaN(expirationDays) && expirationDays > 0) {
        expirationDurationDays = expirationDays;
        expiresAtTimestamp = savedAtTimestamp + (expirationDays * 24 * 60 * 60 * 1000);
  
        localStorage.setItem('consentExpiresAt', expiresAtTimestamp.toString());
        localStorage.setItem('consentExpirationDays', expirationDurationDays.toString());
      } else {
        localStorage.removeItem('consentExpiresAt');
        localStorage.removeItem('consentExpirationDays');
      }
  
      const consentPreferences = buildConsentPreferences(preferences, country, timestamp);
  
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoder = new TextEncoder();
  
      const encryptedPreferences = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(JSON.stringify(consentPreferences))
      );
  
      await storeEncryptedConsent(encryptedPreferences, key, iv, timestamp);
  
      const encryptedVisitorId = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(visitorId)
      );
  
      const rawKey = await crypto.subtle.exportKey("raw", key);
      const b64Key = arrayBufferToBase64(rawKey);
      const b64IV = arrayBufferToBase64(iv);
      const b64EncryptedPreferences = arrayBufferToBase64(encryptedPreferences);
      const b64EncryptedVisitorId = arrayBufferToBase64(encryptedVisitorId);
  
      const payload = {
        clientId,
        encryptedVisitorId: {
          encryptedPreferences: b64EncryptedVisitorId,
          encryptionKey: { key: b64Key, iv: b64IV }
        },
        preferences: {
          encryptedPreferences: b64EncryptedPreferences,
          encryptionKey: { key: b64Key, iv: b64IV }
        },
        policyVersion,
        timestamp,
        country,
        bannerType: currentBannerType,
        expiresAtTimestamp,
        expirationDurationDays,
        metadata: {
          userAgent: navigator.userAgent,
          language: navigator.language,
          platform: navigator.userAgentData?.platform || "unknown",
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
      };
  
      await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(payload),
      });
  
    } catch (error) {
      console.error("Error in saveConsentState:", error);
    }
  }
   




  function buildConsentPreferences(preferences, country, timestamp) {
    return {
      Necessary: true,
      Marketing: preferences.Marketing || false,
      Personalization: preferences.Personalization || false,
      Analytics: preferences.Analytics || false,
      DoNotShare: preferences.ccpa.DoNotShare || false,
      country,
      timestamp,

      gdpr: {
        Necessary: true,
        Marketing: preferences.Marketing || false,
        Personalization: preferences.Personalization || false,
        Analytics: preferences.Analytics || false,
        lastUpdated: timestamp,
        country
      },
      ccpa: {
        Necessary: true,
        DoNotShare: preferences.ccpa.DoNotShare || false,
        lastUpdated: timestamp,
        country
      }
    };
  }

  async function storeEncryptedConsent(encryptedPreferences, key, iv, timestamp) {
    try {
      // Export the key to raw format
      const rawKey = await crypto.subtle.exportKey('raw', key);

      // Ensure the key is exactly 32 bytes
      const keyArray = new Uint8Array(32);
      keyArray.set(new Uint8Array(rawKey));

      localStorage.setItem("consent-given", "true");
      localStorage.setItem("consent-preferences", JSON.stringify({
        encryptedData: arrayBufferToBase64(encryptedPreferences),
        iv: Array.from(iv),
        key: Array.from(keyArray)
      }));

      localStorage.setItem("consent-policy-version", "1.2");
    } catch (error) {
    }
  }
  function buildPayload({ clientId, encryptedVisitorId, encryptedPreferences, encryptionKey, policyVersion, timestamp, country }) {
    return {
      clientId,
      visitorId: {
        encryptedData: encryptedVisitorId,
        iv: Array.from(encryptionKey.iv),
        key: Array.from(new Uint8Array(encryptionKey.secretKey))
      },
      preferences: {
        encryptedData: encryptedPreferences,
        iv: Array.from(encryptionKey.iv),
        key: Array.from(new Uint8Array(encryptionKey.secretKey))
      },
      metadata: {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      policyVersion,
      timestamp,
      country,
      bannerType: currentBannerType
    };
  }


  /*CONSENT  SAVING TO LOCALSTORAGE AND SERVER ENDS*/


  /*Blocking and unblocking */
  function getScriptKey(script) {
    return script.src?.trim() || script.textContent?.trim() || "";
  }

  function getCategoryFromScript(src = "", content = "") {
    const combined = `${src}${content}`.replace(/\s+/g, "");
    for (const { pattern, category } of suspiciousPatterns) {
      if (pattern.test(combined)) {
        return category;
      }
    }
    return null;
  }

  function getCategoryFromContent(content = "") {
    const cleaned = content.replace(/\s+/g, "");
    for (const { pattern, category } of suspiciousPatterns) {
      if (pattern.test(cleaned)) {
        return category;
      }
    }
    return null;
  }

  function isScriptAlreadyBlocked(script) {
    const key = getScriptKey(script);
    return existing_Scripts.some((s) => {
      const existingKey = s.getAttribute("data-original-src")?.trim() || s.textContent?.trim();
      return key === existingKey;
    });
  }

  async function checkAndBlockNewScripts() {
    const categorizedScripts = await loadCategorizedScripts();
    const allScripts = Array.from(document.querySelectorAll("script"));

    const newScripts = allScripts.filter((script) => {
      const isPlain = script.type === "text/plain";
      return !isPlain && !isScriptAlreadyBlocked(script);
    });

    if (newScripts.length === 0) {
      return;
    }

    newScripts.forEach((script) => {
      const src = script.src?.trim();
      const content = script.textContent?.trim();
      const categorized = categorizedScripts.find((s) => s.src === src || s.content === content);

      const category =
        categorized?.category ||
        getCategoryFromScript(src, content) ||
        getCategoryFromContent(content) ||
        "unknown";

      const placeholder = createPlaceholder(script, category);
      if (placeholder) {
        script.parentNode.replaceChild(placeholder, script);
        existing_Scripts.push(placeholder);
      }
    });
  }


  function normalizeUrl(url) {
    return url?.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
  }

  function createPlaceholder(originalScript, category = "uncategorized") {
    const placeholder = document.createElement("script");
    const uniqueId = `consentbit-script-${scriptIdCounter++}`; // Generate a unique ID

    placeholder.type = "text/plain"; // Keep it non-executable
    placeholder.setAttribute("data-consentbit-id", uniqueId); // Store the unique ID
    placeholder.setAttribute("data-category", category);

    const scriptInfo = {
      id: uniqueId,
      category: category.split(',').map(c => c.trim().toLowerCase()), // Store categories as an array
      async: originalScript.async,
      defer: originalScript.defer,
      type: originalScript.type || "text/javascript", // Default type if missing
      originalAttributes: {}
    };

    // Store original src or content
    if (originalScript.src) {
      scriptInfo.src = originalScript.src;
      placeholder.setAttribute("data-original-src", originalScript.src); // Also keep for reference if needed
    } else {
      scriptInfo.content = originalScript.textContent || "";
      // Storing large inline scripts might be memory intensive, consider alternatives if needed
      // placeholder.textContent = originalScript.textContent; // Keep content if needed for inline restoration
    }

    // Store other relevant attributes
    for (const attr of originalScript.attributes) {
      if (!['src', 'type', 'async', 'defer', 'data-category', 'data-consentbit-id'].includes(attr.name)) {
        scriptInfo.originalAttributes[attr.name] = attr.value;
        placeholder.setAttribute(`data-original-${attr.name}`, attr.value); // Optional: keep original attrs on placeholder
      }
    }

    // Add script info to our map
    existing_Scripts[uniqueId] = scriptInfo;

    return placeholder;
  }

  function findCategoryByPattern(text) {
    for (const { pattern, category } of suspiciousPatterns) {
      if (pattern.test(text)) {
        return category;
      }
    }
    return null;

  }


  async function loadCategorizedScripts() {
    try {
      // Get session token from localStorage
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
        return [];
      }

      // Get or generate visitorId
      let visitorId = localStorage.getItem('visitorId');
      if (!visitorId) {
        visitorId = crypto.randomUUID();
        localStorage.setItem('visitorId', visitorId);
      }

      // Get site name from hostname
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];

      // Generate encryption key and IV
      const { key, iv } = await EncryptionUtils.generateKey();

      // Prepare request data
      const requestData = {
        siteName: siteName,
        visitorId: visitorId,
        userAgent: navigator.userAgent
      };

      // Encrypt the request data
      const encryptedRequest = await EncryptionUtils.encrypt(
        JSON.stringify(requestData),
        key,
        iv
      );

      // Send the encrypted request
      const response = await fetch('https://cb-server.web-8fb.workers.dev/api/cmp/script-category', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'X-Request-ID': crypto.randomUUID(),
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Origin': window.location.origin
        },
        body: JSON.stringify({
          encryptedData: encryptedRequest,
          key: Array.from(new Uint8Array(await crypto.subtle.exportKey('raw', key))),
          iv: Array.from(iv)
        })
      });

      if (!response.ok) {
        return [];
      }

      const data = await response.json();

      // Decrypt the response data
      if (data.encryptedData) {
        const responseKey = await EncryptionUtils.importKey(
          new Uint8Array(data.key),
          ['decrypt']
        );

        const decryptedData = await EncryptionUtils.decrypt(
          data.encryptedData,
          responseKey,
          new Uint8Array(data.iv)
        );

        const responseObj = JSON.parse(decryptedData);
        categorizedScripts = responseObj.scripts || [];
        return responseObj.scripts || [];
      } else {
        return [];
      }
    } catch (error) {
      console.log(error);
      return [];
    }
  }


  async function scanAndBlockScripts() {

    const scripts = document.querySelectorAll("script[src]:not([type='text/plain']):not([data-consentbit-id])"); // Select only executable scripts without our ID
    const inlineScripts = document.querySelectorAll("script:not([src]):not([type='text/plain']):not([data-consentbit-id])"); // Select only executable inline scripts without our ID
    const categorizedScriptsList = categorizedScripts || await loadCategorizedScripts(); // Use cached if available

    const normalizedCategorized = categorizedScriptsList?.map(s => {
      // Simple normalization and category extraction for comparison
      const scriptElement = document.createElement('div');
      scriptElement.innerHTML = s.content || '';
      const scriptTag = scriptElement.querySelector('script');
      const categories = scriptTag ? (scriptTag.getAttribute('data-category') || '').split(',').map(c => c.trim()).filter(Boolean) : [];
      return {
        ...s,
        normalizedSrc: normalizeUrl(s.src),
        normalizedContent: (s.content || '').trim().replace(/\s+/g, ''), // More robust content normalization
        categories: categories
      };
    }) || []; // Ensure it's an array


    // Block external scripts
    scripts.forEach(script => {
      const normalizedSrc = normalizeUrl(script.src);
      const matched = normalizedCategorized.find(s => s.normalizedSrc && s.normalizedSrc === normalizedSrc);
      let scriptCategories = matched?.categories || [];

      // If not found by server list, try pattern matching
      if (!matched) {
        const patternCategory = findCategoryByPattern(script.src);
        if (patternCategory) {
          scriptCategories = [patternCategory]; // Pattern provides a single category
        }
      }

      // Only block if categorized (either by server or pattern)
      if (scriptCategories.length > 0) {
        const placeholder = createPlaceholder(script, scriptCategories.join(','));
        if (placeholder && script.parentNode) {
          script.parentNode.replaceChild(placeholder, script);
        }
      }
    });

    // Block inline scripts
    inlineScripts.forEach(script => {
      const content = script.textContent.trim().replace(/\s+/g, ''); // Normalize content
      // Skip empty inline scripts
      if (!content) return;

      // Find based on normalized content (less reliable for inline)
      const matched = normalizedCategorized.find(s => s.normalizedContent && s.normalizedContent === content);
      let scriptCategories = matched?.categories || [];

      // If not found by server list, try pattern matching
      if (!matched) {
        const patternCategory = findCategoryByPattern(script.textContent); // Match raw content
        if (patternCategory) {
          scriptCategories = [patternCategory];
        }
      }

      // Only block if categorized
      if (scriptCategories.length > 0) {
        const placeholder = createPlaceholder(script, scriptCategories.join(','));
        if (placeholder && script.parentNode) {
          script.parentNode.replaceChild(placeholder, script);
        }
      }
    });

    // Setup MutationObserver after initial scan (if not already observing)
    if (!observer) {
      observer = new MutationObserver(handleMutations);
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
    
    function handleMutations(mutationsList) {
      for (const mutation of mutationsList) {
        for (const node of mutation.addedNodes) {
          if (shouldProcessScriptNode(node)) {
            const { categories} = categorizeScript(node);
            if (categories.length > 0) {
              replaceWithPlaceholder(node, categories);
            }
          }
        }
      }
    }
    
    function shouldProcessScriptNode(node) {
      return (
        node.tagName === 'SCRIPT' &&
        !node.hasAttribute('data-consentbit-id') &&
        node.type !== 'text/plain'
      );
    }
    
    function categorizeScript(node) {
      const categories = [];
    
      if (node.src) {
        return { categories: categorizeBySrc(node.src) };
      }
    
      const content = node.textContent.trim().replace(/\s+/g, '');
      if (content) {
        return { categories: categorizeByContent(node.textContent, content) };
      }
    
      return { categories };
    }
    
    function categorizeBySrc(src) {
      const normalizedSrc = normalizeUrl(src);
      const matched = normalizedCategorized.find(s => s.normalizedSrc === normalizedSrc);
      if (matched) return matched.categories;
    
      const patternCategory = findCategoryByPattern(src);
      return patternCategory ? [patternCategory] : [];
    }
    
    function categorizeByContent(rawContent, normalizedContent) {
      const matched = normalizedCategorized.find(s => s.normalizedContent === normalizedContent);
      if (matched) return matched.categories;
    
      const patternCategory = findCategoryByPattern(rawContent);
      return patternCategory ? [patternCategory] : [];
    }
    
    
    function replaceWithPlaceholder(node, categories) {
      const placeholder = createPlaceholder(node, categories.join(','));
      if (placeholder && node.parentNode) {
        node.parentNode.replaceChild(placeholder, node);
      }
    }
    
  }
  async function acceptAllCookies() {

    const allAllowedPreferences = {
      Necessary: true,
      Marketing: true,
      Personalization: true,
      Analytics: true,

      ccpa: { DoNotShare: false } // Example: Assuming accepting all implies sharing is okay
    };

    // 1. Save the "accept all" consent state
    // Ensure saveConsentState uses the correct structure expected by your backend/logic
    await saveConsentState(allAllowedPreferences); // Pass the full preference object

    // 2. Update the preference form display (if visible)
    await updatePreferenceForm(allAllowedPreferences);

    // 3. Restore all scripts based on the new preferences
    // restoreAllowedScripts will now unblock everything based on the map
    await restoreAllowedScripts(allAllowedPreferences);

    // 4. Disconnect the observer *if* desired.
    // If accepting all means no further dynamic blocking is needed.
    // However, if the user can later change preferences back, you might *not* want to disconnect it.
    // Consider the user flow. For now, let's keep it as potentially disconnecting.
    if (observer) {
      observer.disconnect();
      observer = null; // Clear the observer variable
    }

    // 5. Hide banners
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner")); // CCPA
    hideBanner(document.getElementById("main-banner")); // GDPR Preferences
    hideBanner(document.getElementById("main-consent-banner")); // CCPA Preferences
    hideBanner(document.getElementById("simple-consent-banner"));

    localStorage.setItem("consent-given", "true"); // Mark consent as handled

  }
  // Make sure it's globally accessible if called from HTML etc.
  window.acceptAllCookies = acceptAllCookies;
  async function blockAllCookies() {

    const rejectNonNecessaryPreferences = {
      Necessary: true,
      Marketing: false,
      Personalization: false,
      Analytics: false,

      ccpa: { DoNotShare: true }
    };

    await saveConsentState(rejectNonNecessaryPreferences);

    await updatePreferenceForm(rejectNonNecessaryPreferences);

    await restoreAllowedScripts(rejectNonNecessaryPreferences);


    if (!observer) {

      await scanAndBlockScripts();
    }


    // 5. Hide banners
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner")); // CCPA
    hideBanner(document.getElementById("main-banner")); // GDPR Preferences
    hideBanner(document.getElementById("main-consent-banner")); // CCPA Preferences
    hideBanner(document.getElementById("simple-consent-banner"));

    localStorage.setItem("consent-given", "true"); // Mark consent as handled

  }
  // Make sure it's globally accessible if called from HTML etc.
  window.blockAllCookies = blockAllCookies;

  window.blockAllCookies = blockAllCookies;
  window.acceptAllCookies = acceptAllCookies;

  async function loadConsentState() {

    if (isLoadingState) {
      return;
    }
    isLoadingState = true;

    try {
      const consentGiven = localStorage.getItem("consent-given");

      if (consentGiven === "true") {
        try {
          const savedPreferences = localStorage.getItem("consent-preferences");

          if (savedPreferences) {
            const parsedPrefs = JSON.parse(savedPreferences);

            // Create a key from the stored key data
            const key = await crypto.subtle.importKey(
              'raw',
              new Uint8Array(parsedPrefs.key),
              { name: 'AES-GCM' },
              false,
              ['decrypt']
            );

            // Decrypt using the same format as encryption
            const decryptedData = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: new Uint8Array(parsedPrefs.iv) },
              key,
              new Uint8Array(parsedPrefs.encryptedData)
            );

            const preferences = JSON.parse(new TextDecoder().decode(decryptedData));

            // Update consentState
            consentState = {
              Necessary: true,
              Marketing: preferences.Marketing || false,
              Personalization: preferences.Personalization || false,
              Analytics: preferences.Analytics || false,
              ccpa: {
                DoNotShare: preferences.ccpa?.DoNotShare || false
              }
            };

            // Update form using updatePreferenceForm
            await updatePreferenceForm(consentState);

            // Restore allowed scripts based on preferences
            await restoreAllowedScripts(consentState);
          }
        } catch (error) {
          consentState = {
            Necessary: true,
            Marketing: false,
            Personalization: false,
            Analytics: false,
            ccpa: { DoNotShare: false }
          };
          await updatePreferenceForm(consentState);
        }
      } else {
        consentState = {
          Necessary: true,
          Marketing: false,
          Personalization: false,
          Analytics: false,
          ccpa: { DoNotShare: false }
        };
        await updatePreferenceForm(consentState);
      }
    } catch (error) {
      consentState = {
        Necessary: true,
        Marketing: false,
        Personalization: false,
        Analytics: false,
        ccpa: { DoNotShare: false }
      };
      await updatePreferenceForm(consentState);
    } finally {
      isLoadingState = false;
    }

    return consentState;
  }



  async function unblockAllCookiesAndTools() {
    try {
      const allAllowedPreferences = {
        Necessary: true,
        Marketing: true,
        Personalization: true,
        Analytics: true,
        ccpa: { DoNotShare: false }
      };
  
      await saveConsentState(allAllowedPreferences);
      await updatePreferenceForm(allAllowedPreferences);
  
      for (const scriptId of Object.keys(existing_Scripts)) {
        const scriptInfo = existing_Scripts[scriptId];
        if (!scriptInfo) continue;
  
        const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
        if (!placeholder) {
          delete existing_Scripts[scriptId];
          continue;
        }
  
        const script = createRestoredScript(scriptInfo);
        applyScriptSetups(script, scriptInfo.src);
        if (placeholder.parentNode) {
          placeholder.parentNode.replaceChild(script, placeholder);
        } else {
          document.head.appendChild(script);
        }
  
        delete existing_Scripts[scriptId];
      }
  
      localStorage.setItem("consent-given", "true");
  
      if (observer) {
        observer.disconnect();
        observer = null;
      }
  
    } catch (error) {
      console.error("Error unblocking cookies/tools:", error);
    }
  }
  
  function createRestoredScript(scriptInfo) {
    const script = document.createElement("script");
    script.type = scriptInfo.type;
    if (scriptInfo.async) script.async = true;
    if (scriptInfo.defer) script.defer = true;
    script.setAttribute("data-category", scriptInfo.category.join(','));
  
    if (scriptInfo.src) {
      script.src = scriptInfo.src;
    } else {
      script.textContent = scriptInfo.content;
    }
  
    restoreOriginalAttributes(script, scriptInfo.originalAttributes);
    return script;
  }
  
 
  
  function applyScriptSetups(script, src = "") {
    if (!src) return;
  
    if (/googletagmanager\.com\/gtag\/js/.test(src)) setupGoogleAnalytics(script);
    else if (/clarity\.ms/.test(src)) setupClarity();
    else if (/connect\.facebook\.net/.test(src)) setupFacebookPixel(script);
    else if (/matomo\.cloud/.test(src)) setupMatomo(script);
    else if (/hs-scripts\.com/.test(src)) setupHubSpot(script);
    else if (/plausible\.io/.test(src)) setupPlausible(script);
    else if (/static\.hotjar\.com/.test(src)) setupHotjar(script);
    else if (/cdn\.(eu\.)?amplitude\.com/.test(src)) setupAmplitude(script);
  }
  
  // Setup Functions
  function setupGoogleAnalytics(script) {
    script.onload = () => {
      if (typeof gtag === 'function') {
        gtag('consent', 'update', {
          'ad_storage': 'granted',
          'analytics_storage': 'granted',
          'functionality_storage': 'granted',
          'personalization_storage': 'granted',
          'security_storage': 'granted',
          'ad_user_data': 'granted',
          'ad_personalization': 'granted'
        });
      }
    };
  }
  function setupClarity() {
    if (!window.clarity) {
      window.clarity = function (...args) {
        window.clarity.q.push(args);
      };
      window.clarity.q = [];
    } else if (!window.clarity.q) {
      window.clarity.q = [];
    }
  
    window.clarity.consent = true;
  }
  
  function setupFacebookPixel(script) {
    script.onload = () => {
      if (typeof fbq === 'function') fbq('consent', 'grant');
    };
  }
  
  function setupMatomo(script) {
    script.onload = () => {
      if (typeof _paq !== 'undefined') {
        _paq.push(['setConsentGiven']);
        _paq.push(['trackPageView']);
      }
    };
  }
  
  function setupHubSpot(script) {
    script.onload = () => {
      if (typeof _hsq !== 'undefined') _hsq.push(['doNotTrack', { track: true }]);
    };
  }
  
  function setupPlausible(script) {
    script.setAttribute('data-consent-given', 'true');
  }
  
  function setupHotjar(script) {
    if (!window.hj) {
      window.hj = function (...args) {
        window.hj.q.push(args);
      };
      window.hj.q = [];
    } else if (!window.hj.q) {
      window.hj.q = [];
    }
  
    script.onload = () => {
      if (typeof hj === 'function') {
        hj('consent', 'granted');
      }
    };
  }
  
  
  function setupAmplitude(script) {
    script.onload = () => {
      if (typeof amplitude !== 'undefined' && typeof amplitude.setOptOut === 'function') {
        amplitude.setOptOut(false);
      }
    };
    if (typeof amplitude !== 'undefined' && typeof amplitude.setOptOut === 'function') {
      amplitude.setOptOut(true);
    }
  }
  
  window.unblockAllCookiesAndTools = unblockAllCookiesAndTools;
  


  async function restoreAllowedScripts(preferences) {
    const normalizedPrefs = normalizePreferences(preferences);
    const scriptIdsToRestore = Object.keys(existing_Scripts);
  
    for (const scriptId of scriptIdsToRestore) {
      const scriptInfo = existing_Scripts[scriptId];
      if (!scriptInfo) continue;
  
      const placeholder = findPlaceholder(scriptId);
      if (!placeholder) {
        delete existing_Scripts[scriptId];
        continue;
      }
  
      const isAllowed = scriptInfo.category.some(cat => normalizedPrefs[cat] === true);
      if (!isAllowed) {
        validatePlaceholder(placeholder);
        continue;
      }
  
      if (shouldSkipDueToExistingScript(scriptInfo, placeholder)) {
        delete existing_Scripts[scriptId];
        continue;
      }
  
      const restoredScript = buildScriptElement(scriptInfo, normalizedPrefs);
  
      if (placeholder.parentNode) {
        placeholder.parentNode.replaceChild(restoredScript, placeholder);
      } else {
        document.head.appendChild(restoredScript);
      }
  
      delete existing_Scripts[scriptId];
    }
  }
  
  function normalizePreferences(preferences) {
    return Object.fromEntries(
      Object.entries(preferences).map(([key, value]) => [key.toLowerCase(), value])
    );
  }
  
  function findPlaceholder(scriptId) {
    return document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
  }
  
  function validatePlaceholder(placeholder) {
    if (placeholder.tagName !== 'SCRIPT' || placeholder.type !== 'text/plain') {
      // Placeholder is not valid anymore, optionally re-block
    }
  }
  
  function shouldSkipDueToExistingScript(scriptInfo, placeholder) {
    if (scriptInfo.src) {
      const existingScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain'])`);
      if (existingScript && existingScript !== placeholder) {
        placeholder.parentNode?.removeChild(placeholder);
        return true;
      }
    }
    return false;
  }
  
  function buildScriptElement(scriptInfo, normalizedPrefs) {
    const script = document.createElement("script");
    script.type = scriptInfo.type;
    if (scriptInfo.async) script.async = true;
    if (scriptInfo.defer) script.defer = true;
    script.setAttribute("data-category", scriptInfo.category.join(','));
  
    if (scriptInfo.src) {
      script.src = scriptInfo.src;
      handleSpecialCases(script, scriptInfo, normalizedPrefs);
    } else {
      script.textContent = scriptInfo.content;
      restoreOriginalAttributes(script, scriptInfo.originalAttributes);
    }
  
    return script;
  }
  
  function restoreOriginalAttributes(script, attributes) {
    Object.entries(attributes).forEach(([name, value]) => {
      script.setAttribute(name, value);
    });
  }
  
  function handleSpecialCases(script, scriptInfo, normalizedPrefs) {
    const src = scriptInfo.src;
    if (/googletagmanager\.com\/gtag\/js/i.test(src)) {
      script.onload = () => updateGAConsent(normalizedPrefs);
      updateGAConsent(normalizedPrefs);
    } else if (/amplitude|amplitude.com/i.test(src)) {
      script.onload = () => updateAmplitudeConsent(normalizedPrefs);
      updateAmplitudeConsent(normalizedPrefs);
    } else {
      restoreOriginalAttributes(script, scriptInfo.originalAttributes);
    }
  }
  
  function updateGAConsent(prefs) {
    if (typeof gtag === "function") {
      gtag('consent', 'update', {
        'ad_storage': prefs.marketing ? 'granted' : 'denied',
        'analytics_storage': prefs.analytics ? 'granted' : 'denied',
        'ad_personalization': prefs.marketing ? 'granted' : 'denied',
        'ad_user_data': prefs.marketing ? 'granted' : 'denied'
      });
    }
  }
  
  function updateAmplitudeConsent(prefs) {
    if (typeof amplitude !== "undefined" && amplitude.getInstance) {
      const instance = amplitude.getInstance();
      instance.setOptOut(!prefs.analytics);
      instance.setUserProperties({
        consent_analytics: prefs.analytics,
        consent_marketing: prefs.marketing,
        consent_personalization: prefs.personalization || false
      });
    }
  }
  


  /* INITIALIZATION */
  async function getVisitorSessionToken() {
    try {
      // Check if we have a valid token in localStorage first
      const existingToken = localStorage.getItem('visitorSessionToken');
      if (existingToken && !isTokenExpired(existingToken)) {
        return existingToken;
      }

      // Get or create visitor ID
      const visitorId = await getOrCreateVisitorId();

      // Get cleaned site name
      const siteName = await cleanHostname(window.location.hostname);

      const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          visitorId: visitorId,
          userAgent: navigator.userAgent,
          siteName: siteName
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to get visitor session token: ${response.status}`);
      }

      const data = await response.json();

      // Store the new token
      localStorage.setItem('visitorSessionToken', data.token);

      return data.token;
    } catch (error) {
      return null;
    }
  }



  async function loadConsentStyles() {
    try {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css";
      link.type = "text/css";
      const link2 = document.createElement("link");
      link2.rel = "stylesheet";
      link2.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css";
      document.head.appendChild(link2);


      // Add error handling
      link.onerror = function () {
      };

      // Add load confirmation
      link.onload = function () {
      };

      document.head.appendChild(link);
    } catch (error) {
    }
  }
  window.loadConsentStyles = loadConsentStyles;
  window.loadConsentState = loadConsentState;
  window.scanAndBlockScripts = scanAndBlockScripts;
  window.initializeBanner = initializeBanner;
  window.attachBannerHandlers = attachBannerHandlers;
  window.showBanner = showBanner;
  window.hideBanner = hideBanner;
  window.checkAndBlockNewScripts = checkAndBlockNewScripts;
  window.createPlaceholder = createPlaceholder;
  window.restoreAllowedScripts = restoreAllowedScripts;
  window.loadCategorizedScripts = loadCategorizedScripts;
  window.detectLocationAndGetBannerType = detectLocationAndGetBannerType;
  window.getVisitorSessionToken = getVisitorSessionToken;
  window.isTokenExpired = isTokenExpired;
  window.cleanHostname = cleanHostname;
  window.getOrCreateVisitorId = getOrCreateVisitorId;
  window.buildConsentPreferences = buildConsentPreferences;
  window.storeEncryptedConsent = storeEncryptedConsent;
  window.buildPayload = buildPayload;
  window.getClientIdentifier = getClientIdentifier;
  window.getScriptKey = getScriptKey;
  window.getCategoryFromScript = getCategoryFromScript;
  window.getCategoryFromContent = getCategoryFromContent;
  window.isScriptAlreadyBlocked = isScriptAlreadyBlocked;
  window.findCategoryByPattern = findCategoryByPattern;
  window.normalizeUrl = normalizeUrl;
  window.blockAllInitialRequests = blockAllInitialRequests;
  window.reblockDisallowedScripts = reblockDisallowedScripts;

  document.addEventListener('DOMContentLoaded', initialize);
  async function isCookieExpired() {
    let isCookieExpired = false;

    const storedExpiresAtString = localStorage.getItem('consentExpiresAt');
    const isConsentGiven = localStorage.getItem('consent-given');
    if (storedExpiresAtString && isConsentGiven) {
      const expiresAtTimestamp = parseInt(storedExpiresAtString, 10);

      const currentTimestamp = Date.now();
      if (currentTimestamp > expiresAtTimestamp) {
        console.log("Consent has expired.");
        isCookieExpired = !isCookieExpired;
      }
      if (isCookieExpired) {

        localStorage.removeItem("consent-given");
        localStorage.removeItem("consent-preferences");
        localStorage.removeItem('consentExpiresAt');
        localStorage.removeItem('consentExpirationDays');
        return true;
      }

      return false;


    }
  }

  async function loadAndApplySavedPreferences() {

    if (isLoadingState) {

      return;
    }
    isLoadingState = true;

    try {
      const consentGiven = localStorage.getItem("consent-given");



      if (consentGiven === "true") {





        const savedPreferences = localStorage.getItem("consent-preferences");
        if (savedPreferences) {
          try {
            const parsedPrefs = JSON.parse(savedPreferences);

            // Ensure we have a proper 256-bit key
            const keyData = new Uint8Array(parsedPrefs.key);
            if (keyData.length !== 32) { // 256 bits = 32 bytes
              throw new Error("Invalid key length");
            }

            // Import the key
            const key = await crypto.subtle.importKey(
              'raw',
              keyData,
              { name: 'AES-GCM', length: 256 }, // Specify the key length
              false,
              ['decrypt']
            );

            // Convert base64 encrypted data back to ArrayBuffer
            const encryptedData = base64ToArrayBuffer(parsedPrefs.encryptedData);

            const decryptedData = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: new Uint8Array(parsedPrefs.iv) },
              key,
              encryptedData
            );


            const preferences = JSON.parse(new TextDecoder().decode(decryptedData));

            // Normalize preferences structure
            const normalizedPreferences = {
              Necessary: true,
              Marketing: preferences.Marketing || false,
              Personalization: preferences.Personalization || false,
              Analytics: preferences.Analytics || false,
              ccpa: {
                DoNotShare: preferences.ccpa?.DoNotShare || false
              }
            };

            // Update form
            await updatePreferenceForm(normalizedPreferences);

            // Unblock allowed scripts
            await restoreAllowedScripts(normalizedPreferences);

            return normalizedPreferences;
          } catch (error) {
            localStorage.removeItem("consent-preferences");
          }
        }
      }

    } catch (error) {
    } finally {
      isLoadingState = false;
    }

    // Default preferences if nothing was loaded
    return {
      Necessary: true,
      Marketing: false,
      Personalization: false,
      Analytics: false,
      ccpa: { DoNotShare: false }
    };
  }
  window.isCookieExpired = isCookieExpired;
  // Helper functions for base64 conversion
  function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }


  
  async function updatePreferenceForm(preferences) {


    // Get checkbox elements
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
    const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
    const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
    const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
    const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');

    if (!necessaryCheckbox && !marketingCheckbox && !personalizationCheckbox &&
      !analyticsCheckbox && !doNotShareCheckbox) {
      return;
    }
    // Update necessary checkbox
    if (necessaryCheckbox) {
      necessaryCheckbox.checked = true;
      necessaryCheckbox.disabled = true; // Always disabled
    }

    // Update other checkboxes
    if (marketingCheckbox) {
      marketingCheckbox.checked = Boolean(preferences.Marketing);
    }

    if (personalizationCheckbox) {
      personalizationCheckbox.checked = Boolean(preferences.Personalization);
    }

    if (analyticsCheckbox) {
      analyticsCheckbox.checked = Boolean(preferences.Analytics);
    }

    if (doNotShareCheckbox) {
      doNotShareCheckbox.checked = Boolean(preferences.ccpa?.DoNotShare);
    }


  }

  // Modify initialize function
  async function initialize() {

    try {
      const token = await getVisitorSessionToken();
      if (!token) {
        setTimeout(initialize, 2000);
        return;
      }

      // Store token in localStorage if not already there
      if (!localStorage.getItem('visitorSessionToken')) {
        localStorage.setItem('visitorSessionToken', token);
      }

      await isCookieExpired();
      const preferences = await loadAndApplySavedPreferences();
      const banner = await detectLocationAndGetBannerType();
      if (banner.bannerType === 'GDPR') {
        // Only proceed with normal initialization if no preferences
        if (!preferences || !localStorage.getItem("consent-given")) {
          await scanAndBlockScripts();
          await initializeBannerVisibility();
        }
      }
      else if (banner.bannerType === 'CCPA') {
        if (!preferences || !localStorage.getItem("consent-given")) {

          await initializeBannerVisibility();

        }

      }



      // Always load these
      await loadConsentStyles();
      

      // Hide banners if consent was given
      if (localStorage.getItem("consent-given") === "true") {
        hideBanner(document.getElementById("consent-banner"));
        hideBanner(document.getElementById("initial-consent-banner"));
        hideBanner(document.getElementById("main-banner"));
        hideBanner(document.getElementById("main-consent-banner"));
        hideBanner(document.getElementById("simple-consent-banner"));
      }

      attachBannerHandlers();
    } catch (error) {

      setTimeout(initialize, 2000);
    }

  }
  // Add to your window exports
  window.loadAndApplySavedPreferences = loadAndApplySavedPreferences;
  window.updatePreferenceForm = updatePreferenceForm;

})();



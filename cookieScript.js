(async function () {
    const existing_Scripts = {};
    let scriptIdCounter = 0;
    let isLoadingState = false;
    let consentState = {};
    let observer;
    let isInitialized = false;
    let currentBannerType = null;
    let country = null;
    let categorizedScripts = null;
    let initialBlockingEnabled = true; // Default to true (GDPR-like) until determined otherwise
  
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
  
  const EncryptionUtils = {
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
          // Ensure rawKey is an ArrayBuffer or TypedArray
          let keyMaterial = rawKey;
          if (Array.isArray(rawKey)) {
               keyMaterial = new Uint8Array(rawKey);
          } else if (!(rawKey instanceof ArrayBuffer) && !ArrayBuffer.isView(rawKey)) {
               console.error("Invalid key format for importKey. Expected ArrayBuffer, TypedArray, or Array.");
               throw new Error("Invalid key format for importKey");
          }
  
          return await crypto.subtle.importKey(
              'raw',
              keyMaterial,
              { name: 'AES-GCM' },
              false, // Key is not extractable after import
              usages
          );
      },
  
  
      async encrypt(data, key, iv) {
          const encoder = new TextEncoder();
          const encodedData = encoder.encode(data);
          const encrypted = await crypto.subtle.encrypt(
              { name: 'AES-GCM', iv }, // IV should be Uint8Array
              key,
              encodedData
          );
          // Return ArrayBuffer directly or convert to base64 outside if needed
          return encrypted; // Return ArrayBuffer
          // return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
      },
  
      async decrypt(encryptedData, key, iv) {
           // Ensure encryptedData is ArrayBuffer or TypedArray
          let dataBuffer = encryptedData;
          if (typeof encryptedData === 'string') { // Assume base64 if string
               dataBuffer = base64ToArrayBuffer(encryptedData);
          } else if (!(encryptedData instanceof ArrayBuffer) && !ArrayBuffer.isView(encryptedData)) {
               console.error("Invalid encryptedData format for decrypt. Expected ArrayBuffer, TypedArray, or base64 string.");
               throw new Error("Invalid encryptedData format for decrypt");
          }
  
          const decrypted = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv }, // IV should be Uint8Array
              key,
              dataBuffer
          );
          return new TextDecoder().decode(decrypted);
      }
    };
  
  
   function isTokenExpired(token) {
      try {
          const [headerBase64, payloadBase64, signatureBase64] = token.split('.');
          if (!payloadBase64 || !signatureBase64) { // Check for payload and signature
              console.error("Invalid token format: Missing payload or signature.");
              return true;
          }
          // Use TextDecoder for potentially better UTF-8 handling
          const decoder = new TextDecoder();
          const payloadString = decoder.decode(base64ToArrayBuffer(payloadBase64.replace(/-/g, '+').replace(/_/g, '/')));
          const payload = JSON.parse(payloadString);
  
          if (typeof payload.exp !== 'number') { // Check type
              console.warn("Token payload does not contain a valid 'exp' field (must be a number).");
              return true; // Treat tokens without valid expiration as expired/invalid
          }
  
          const isExpired = payload.exp < Math.floor(Date.now() / 1000);
          // console.log(`Token expiration check: exp=${payload.exp}, now=${Math.floor(Date.now() / 1000)}, expired=${isExpired}`);
          return isExpired;
      } catch (error) {
          // Log the specific error encountered during parsing or decoding
          console.error("Error validating token:", error);
          // Treat any error during validation as if the token is expired/invalid
          return true;
      }
  }
  
   // Function to clean hostname
  async function cleanHostname(hostname) {
      let cleaned = hostname.replace(/^www\./, '');
      // Return only the site name part if needed, or the full cleaned name
      // cleaned = cleaned.split('.')[0]; // Uncomment if only the first part is needed
      return cleaned;
  }
  
  // Function to generate or get visitor ID
  async function getOrCreateVisitorId() {
      let visitorId = localStorage.getItem('visitorId');
      if (!visitorId) {
          visitorId = crypto.randomUUID();
          localStorage.setItem('visitorId', visitorId);
          console.log("Created new visitorId:", visitorId);
      }
      return visitorId;
  }
  
  async function detectLocationAndGetBannerType() {
    try {
        const sessionToken = localStorage.getItem('visitorSessionToken');
        if (!sessionToken || isTokenExpired(sessionToken)) { // Check for token and expiry
             if (!sessionToken) console.warn("No visitorSessionToken found for location detection.");
             if (sessionToken && isTokenExpired(sessionToken)) console.warn("VisitorSessionToken is expired.");
            return null;
        }
        const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
        const apiUrl = `https://cb-server.web-8fb.workers.dev/api/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`;
        console.log("Fetching location data from:", apiUrl);
  
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${sessionToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            mode: 'cors' // Ensure CORS mode is set if fetching cross-origin
        });
  
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Error fetching location data (${response.status}): ${errorText}`);
            return null;
        }
  
        const data = await response.json();
  
        if (!data || typeof data !== 'object' || !data.bannerType) { // Add more robust checks
            console.warn("Location data received, but format is invalid or bannerType is missing:", data);
            return null;
        }
        country = data.country; // Assign to global scope
        console.log(`Location detected: Country=${country}, BannerType=${data.bannerType}`);
        return { bannerType: data.bannerType, country: data.country }; // Return object
    } catch (error) {
        console.error("Error during detectLocationAndGetBannerType fetch or processing:", error);
        return null;
    }
  }
  
  function getClientIdentifier() {
      return window.location.hostname;
  }
  
  // --- REMOVED: reblockDisallowedScripts function (buggy and redundant) ---
  /*
  async function reblockDisallowedScripts(consentState) {
      // ... (removed buggy code referencing undefined 'blockedScripts') ...
  }
  */
  // --- END REMOVED ---
  
  
  /*BANNER */
  
  /** Helper Functions for attachBannerHandlers **/
  
  // Helper function to attach event listeners safely
  function attachListener(id, event, handler) {
    const element = document.getElementById(id);
    if (element) {
        element.addEventListener(event, handler);
    } else {
        // console.warn(`Element with ID "${id}" not found for attaching listener.`);
    }
  }
  
  // --- Individual Event Handler Functions ---
  
  async function handleSimpleAccept(e) {
    e.preventDefault();
    const simpleBanner = document.getElementById("simple-consent-banner");
    const preferences = { Necessary: true, Marketing: true, Personalization: true, Analytics: true, ccpa: { DoNotShare: false } };
    await saveConsentState(preferences);
    await restoreAllowedScripts(preferences);
    if (simpleBanner) hideBanner(simpleBanner);
    localStorage.setItem("consent-given", "true");
  }
  
  async function handleSimpleReject(e) {
    e.preventDefault();
    const simpleBanner = document.getElementById("simple-consent-banner");
    const preferences = { Necessary: true, Marketing: false, Personalization: false, Analytics: false, ccpa: { DoNotShare: true } }; // Reject implies DoNotShare=true?
    await saveConsentState(preferences);
    // --- MODIFIED: Call scanAndBlockScripts to ensure blocking and observer are active ---
    await scanAndBlockScripts(); // Ensure blocking + observer after reject
    // --- END MODIFIED ---
    if (simpleBanner) hideBanner(simpleBanner);
    localStorage.setItem("consent-given", "true");
  }
  
  function handleToggleConsent(e) {
    e.preventDefault();
    const consentBanner = document.getElementById("consent-banner"); // GDPR
    const ccpaBanner = document.getElementById("initial-consent-banner"); // CCPA initial
    const mainConsentBanner = document.getElementById("main-consent-banner"); // CCPA Prefs
    const mainBanner = document.getElementById("main-banner"); // GDPR Prefs
  
    // Use the most recently determined banner type
    const type = currentBannerType;
  
    console.log(`Toggling consent banner visibility. Current detected type: ${type}`);
  
    // Hide all potentially visible banners first
    if (consentBanner) hideBanner(consentBanner);
    if (ccpaBanner) hideBanner(ccpaBanner);
    if (mainConsentBanner) hideBanner(mainConsentBanner);
    if (mainBanner) hideBanner(mainBanner);
  
    // Decide which banner to show based on consent state and type
    const prefs = consentState;
    const consentGiven = localStorage.getItem("consent-given") === "true";
  
    if (consentGiven && prefs) {
        // If consent exists, show the appropriate *preferences* banner
        if (type === 'CCPA') {
            console.log("Showing CCPA preferences banner.");
            if (mainConsentBanner) showBanner(mainConsentBanner);
        } else { // Assume GDPR or default
            console.log("Showing GDPR preferences banner.");
            if (mainBanner) showBanner(mainBanner);
        }
    } else {
        // If no consent given yet, show the initial banner for the region
        if (type === 'CCPA') {
            console.log("Showing initial CCPA banner.");
            if (ccpaBanner) showBanner(ccpaBanner);
        } else { // Assume GDPR or default
            console.log("Showing initial GDPR banner.");
            if (consentBanner) showBanner(consentBanner);
        }
    }
  }
  
  function handleDoNotShareLinkClick(e) {
    e.preventDefault();
    const ccpaBanner = document.getElementById("initial-consent-banner");
    const mainConsentBanner = document.getElementById("main-consent-banner");
    if (ccpaBanner) hideBanner(ccpaBanner);
    if (mainConsentBanner) showBanner(mainConsentBanner);
  }
  
  function handleCloseConsentBanner(e) {
    e.preventDefault();
    // Close the specific banner this button is on (likely main CCPA or GDPR prefs)
    const banner = e.target.closest('.consent-banner-class'); // Add a common class to banners
    if (banner) {
       hideBanner(banner);
    } else {
       // Fallback for specific IDs if needed
       const mainConsentBanner = document.getElementById("main-consent-banner");
       const mainBanner = document.getElementById("main-banner");
       if (mainConsentBanner && mainConsentBanner.contains(e.target)) hideBanner(mainConsentBanner);
       if (mainBanner && mainBanner.contains(e.target)) hideBanner(mainBanner);
    }
  }
  
  async function handleAcceptAll(e) {
    e.preventDefault();
    await acceptAllCookies();
  }
  
  async function handleDeclineAll(e) {
    e.preventDefault();
    await blockAllCookies();
  }
  
  function handleShowPreferences(e) {
    e.preventDefault();
    const consentBanner = document.getElementById("consent-banner"); // GDPR initial banner
    const mainBanner = document.getElementById("main-banner");       // GDPR preferences
    if(consentBanner) hideBanner(consentBanner);
    if(mainBanner) showBanner(mainBanner);
  }
  
  async function handleSaveGdprPreferences(e) {
    e.preventDefault();
    const marketingCheckbox = document.querySelector('#main-banner [data-consent-id="marketing-checkbox"]'); // Scope query
    const personalizationCheckbox = document.querySelector('#main-banner [data-consent-id="personalization-checkbox"]');
    const analyticsCheckbox = document.querySelector('#main-banner [data-consent-id="analytics-checkbox"]');
    const preferences = {
        Necessary: true,
        Marketing: marketingCheckbox?.checked || false,
        Personalization: personalizationCheckbox?.checked || false,
        Analytics: analyticsCheckbox?.checked || false,
        ccpa: { DoNotShare: false } // GDPR form doesn't set this directly
    };
    try {
        await saveConsentState(preferences);
        await restoreAllowedScripts(preferences); // Restore based on new prefs
    } catch (error) {
        console.error("Error saving GDPR preferences:", error);
    }
    const consentBanner = document.getElementById("consent-banner");
    const mainBanner = document.getElementById("main-banner");
    if(consentBanner) hideBanner(consentBanner);
    if(mainBanner) hideBanner(mainBanner);
    localStorage.setItem("consent-given", "true");
  }
  
  async function handleSaveCcpaPreferences(e) {
    e.preventDefault();
    const doNotShareCheckbox = document.querySelector('#main-consent-banner [data-consent-id="do-not-share-checkbox"]'); // Scope query
    const doNotShare = doNotShareCheckbox?.checked || false;
  
    const preferences = {
        Necessary: true,
        Marketing: !doNotShare,
        Personalization: !doNotShare,
        Analytics: !doNotShare,
        ccpa: { DoNotShare: doNotShare }
    };
  
    try {
        await saveConsentState(preferences);
        await restoreAllowedScripts(preferences);
  
        if (doNotShare) {
            // --- MODIFIED: Ensure observer is active ---
            if (!observer) {
                 console.log("CCPA DoNotShare=true: Ensuring observer is active.");
                 await scanAndBlockScripts(); // Ensure blocking + observer
             }
            // --- END MODIFIED ---
        } else {
            if (observer) {
                 observer.disconnect();
                 observer = null;
                 console.log("MutationObserver disconnected (CCPA DoNotShare=false).");
             }
        }
  
    } catch (error) {
        console.error("Error saving CCPA preferences:", error);
    }
  
    const initialCcpaBanner = document.getElementById("initial-consent-banner");
    const mainCcpaBanner = document.getElementById("main-consent-banner");
    if(initialCcpaBanner) hideBanner(initialCcpaBanner);
    if(mainCcpaBanner) hideBanner(mainCcpaBanner);
    localStorage.setItem("consent-given", "true");
  }
  
  async function handleCancelPreferences(e) {
    e.preventDefault();
    console.log("Cancel preferences clicked.");
    // Define preferences as declined (only Necessary is true)
    // For CCPA, cancelling often means reverting to the state *before* opening prefs
    // For GDPR, cancelling usually means keeping the previously saved state or declining all.
    // Let's assume cancelling means declining all non-necessary for simplicity here.
    const preferences = {
        Necessary: true, Marketing: false, Personalization: false, Analytics: false,
        ccpa: { DoNotShare: true } // Declining implies DoNotShare = true? Or revert? Assume true.
    };
  
    // Save the declined state
    await saveConsentState(preferences);
    // Re-apply blocking based on declined state
    await restoreAllowedScripts(preferences);
     // --- MODIFIED: Ensure observer is running ---
     if (!observer) {
         console.log("Cancel Prefs: Ensuring observer is active.");
         await scanAndBlockScripts(); // Ensure blocking + observer
     }
     // --- END MODIFIED ---
  
    // Hide the preference banners
    const mainBanner = document.getElementById("main-banner"); // GDPR Prefs
    const mainConsentBanner = document.getElementById("main-consent-banner"); // CCPA Prefs
    if (mainBanner) hideBanner(mainBanner);
    if (mainConsentBanner) hideBanner(mainConsentBanner);
  
    // Optionally show the initial banner again? Depends on desired UX.
    // For now, just hide prefs banners. The main init logic handles showing initial banners.
  
    localStorage.setItem("consent-given", "true"); // Mark consent as handled (even if declined)
  }
  
  
  // --- Refactored attachBannerHandlers Function ---
  
  async function attachBannerHandlers() {
    // Setup necessary checkbox (simple enough to keep inline)
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]'); // Might be in multiple forms
    if (necessaryCheckbox) {
        necessaryCheckbox.checked = true;
        necessaryCheckbox.disabled = true;
    }
  
    // Attach listeners using the helper
    attachListener("simple-accept", "click", handleSimpleAccept);
    attachListener("simple-reject", "click", handleSimpleReject);
    attachListener("toggle-consent-btn", "click", handleToggleConsent);
    attachListener("new-toggle-consent-btn", "click", handleToggleConsent); // Check if this ID exists
    attachListener("do-not-share-link", "click", handleDoNotShareLinkClick);
    attachListener("close-consent-banner", "click", handleCloseConsentBanner); // Check if this ID exists or use class selector
  
    // Generic Accept/Decline (assuming IDs apply to both GDPR/CCPA main banners, might need scoping)
    attachListener("accept-btn", "click", handleAcceptAll);
    attachListener("decline-btn", "click", handleDeclineAll);
  
    // GDPR Specific
    attachListener("preferences-btn", "click", handleShowPreferences); // GDPR initial banner -> GDPR prefs
    attachListener("save-preferences-btn", "click", handleSaveGdprPreferences); // GDPR Save Prefs
  
    // CCPA Specific (assuming 'save-btn' is CCPA save, verify ID)
    attachListener("save-btn", "click", handleSaveCcpaPreferences); // CCPA Save Prefs
  
    // Generic Cancel (assuming ID applies to both GDPR/CCPA prefs banners, might need scoping)
    attachListener("cancel-btn", "click", handleCancelPreferences);
  
    console.log("Banner event handlers attached.");
  }
  
  // --- MODIFIED: initializeBannerVisibility only determines type and country ---
  async function initializeBannerVisibility() {
      console.log("Determining banner visibility requirements...");
      const locationData = await detectLocationAndGetBannerType();
      // Assign results to global scope vars
      currentBannerType = locationData?.bannerType;
      country = locationData?.country;
      console.log(`Banner visibility check complete. Type: ${currentBannerType}, Country: ${country}`);
      // Banner showing logic is now handled in initializeConsentManagement
  }
  // --- END MODIFIED ---\n\n// --- MODIFIED: initializeBanner only attaches handlers ---
  function initializeBanner() {
      console.log("Initializing banner (attaching handlers)...");
      // Wait for DOM to be fully loaded before attaching handlers
      if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', attachBannerHandlers);
      } else {
          attachBannerHandlers(); // Attach handlers immediately if DOM is ready
      }
      // Visibility determination and showing are handled by initializeConsentManagement
  }
  // --- END MODIFIED ---
  
  function showBanner(banner) {
      if (banner && typeof banner === 'object' && typeof banner.style !== 'undefined') {
        console.log(`Showing banner: #${banner.id}`);
        banner.style.display = "block"; // Or flex, grid, etc. depending on CSS
        // Use classes for transitions/animations if preferred
        // banner.classList.add("show-banner");
        // banner.classList.remove("hidden");
      } else {
        console.warn("showBanner called with invalid banner element:", banner);
      }
  }
  
  function hideBanner(banner) {
      if (banner && typeof banner === 'object' && typeof banner.style !== 'undefined') {
         console.log(`Hiding banner: #${banner.id}`);
        banner.style.display = "none";
        // banner.classList.remove("show-banner");
        // banner.classList.add("hidden");
      } else {
         // console.warn("hideBanner called with invalid banner element:", banner);
      }
  }
  
  
  
  async function saveConsentState(preferences) {
    console.log("Saving consent state:", preferences);
    const clientId = getClientIdentifier();
    // --- MODIFIED: Use getOrCreateVisitorId ---
    const visitorId = await getOrCreateVisitorId(); // Ensure visitorId exists
    // --- END MODIFIED ---
    const policyVersion = "1.2"; // Consider making dynamic?
    const timestamp = new Date().toISOString();
    const sessionToken = localStorage.getItem("visitorSessionToken");
  
    // Always save locally first
    await storeEncryptedConsentLocally(preferences, country, timestamp);
  
    // Attempt server save only if token exists and is valid
    if (!sessionToken || isTokenExpired(sessionToken)) {
      if (!sessionToken) console.warn("No session token found. Cannot save consent state to server.");
      if (sessionToken && isTokenExpired(sessionToken)) console.warn("Session token expired. Cannot save consent state to server.");
      return; // Stop here if no valid token
    }
  
    try {
      // Prepare data for encryption
      const consentPreferencesForEncryption = buildConsentPreferences(preferences, country, timestamp);
      const prefsJson = JSON.stringify(consentPreferencesForEncryption);
      const visitorIdJson = JSON.stringify({ visitorId: visitorId }); // Encrypt as object if needed
  
      // 1. Generate *fresh* AES-GCM key and IV for this save operation
      const { key, iv } = await EncryptionUtils.generateKey();
      const ivBytes = new Uint8Array(iv); // Ensure iv is Uint8Array
  
      // 2. Encrypt preferences and visitorId
      const encryptedPreferencesBuffer = await EncryptionUtils.encrypt(prefsJson, key, ivBytes);
      const encryptedVisitorIdBuffer = await EncryptionUtils.encrypt(visitorIdJson, key, ivBytes); // Using same key/iv
  
      // 3. Export raw key
      const rawKey = await crypto.subtle.exportKey("raw", key);
      const keyArray = new Uint8Array(32); // Ensure 32 bytes
      const exportedKeyBytes = new Uint8Array(rawKey);
      keyArray.set(exportedKeyBytes.slice(0, 32));
  
      // 4. Convert everything to Base64 for JSON payload
      const b64Key = arrayBufferToBase64(keyArray.buffer);
      const b64IV = arrayBufferToBase64(ivBytes.buffer);
      const b64EncryptedPreferences = arrayBufferToBase64(encryptedPreferencesBuffer);
      const b64EncryptedVisitorId = arrayBufferToBase64(encryptedVisitorIdBuffer);
  
      // 5. Build final payload (Adjust structure based on server expectations)
      const payload = {
        clientId,
        encryptedVisitorId: b64EncryptedVisitorId,
        visitorIdEncryptionKey: { key: b64Key, iv: b64IV },
        encryptedPreferences: b64EncryptedPreferences,
        preferencesEncryptionKey: { key: b64Key, iv: b64IV },
        policyVersion,
        timestamp,
        country,
        bannerType: currentBannerType, // Send the detected type
        metadata: {
          userAgent: navigator.userAgent,
          language: navigator.language,
          platform: navigator.platform,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
      };
  
      // 6. Send payload to server
      console.log("Sending consent payload to server...");
      const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(payload),
        mode: 'cors' // Ensure CORS mode
      });
  
      const responseText = await response.text();
      if (!response.ok) {
          console.error(`Failed to save consent to server (${response.status}): ${responseText}`);
      } else {
           console.log("Consent saved successfully to server:", responseText);
      }
    } catch (error) {
        console.error("Error encrypting or sending consent state:", error);
    }
  }
  
  // Helper: Convert ArrayBuffer → base64
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  
  // Helper: Convert base64 → ArrayBuffer (needed for decryption)
  function base64ToArrayBuffer(base64) {
      const binary_string = atob(base64.replace(/-/g, '+').replace(/_/g, '/')); // Handle URL-safe base64
      const len = binary_string.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
          bytes[i] = binary_string.charCodeAt(i);
      }
      return bytes.buffer;
  }
  
  
  function buildConsentPreferences(preferences, country, timestamp) {
      // Build a flat structure, more common for storage/transmission
      const flatPrefs = {
        // Consent categories
        Necessary: true, // Always true
        Marketing: preferences.Marketing || false,
        Personalization: preferences.Personalization || false,
        Analytics: preferences.Analytics || false,
        // CCPA specific flag (normalize access)
        DoNotShare: preferences.ccpa?.DoNotShare ?? preferences.DoNotShare ?? false, // Use nullish coalescing
        // Metadata
        consentTimestamp: timestamp,
        consentPolicyVersion: "1.2", // Hardcoded or get dynamically
        consentCountry: country || 'Unknown', // Include detected country
        bannerType: currentBannerType || 'Unknown' // Include detected banner type
      };
      // console.log("Built consent preferences object:", flatPrefs);
      return flatPrefs;
  }
  
  // --- MODIFIED: storeEncryptedConsentLocally uses buildConsentPreferences ---
  async function storeEncryptedConsentLocally(preferences, country, timestamp) {
    try {
        // 1. Build the standard preferences object
        const consentPreferencesToStore = buildConsentPreferences(preferences, country, timestamp);
  
        // 2. Generate a key and IV specifically for local storage encryption
        const { key, iv } = await EncryptionUtils.generateKey();
        const ivBytes = new Uint8Array(iv); // Ensure Uint8Array
  
        // 3. Encrypt the built preferences object
        const encryptedPreferencesBuffer = await EncryptionUtils.encrypt(
            JSON.stringify(consentPreferencesToStore),
            key,
            ivBytes
        );
  
        // 4. Export the key for storage
        const rawKey = await crypto.subtle.exportKey('raw', key);
        const keyArray = new Uint8Array(32);
        const exportedKeyBytes = new Uint8Array(rawKey);
        keyArray.set(exportedKeyBytes.slice(0, 32));
        if (exportedKeyBytes.length !== 32) {
            console.warn(`Local storage key was ${exportedKeyBytes.length} bytes, expected 32. Key adjusted.`);
        }
  
        // 5. Store encrypted data, IV, and key in localStorage
        localStorage.setItem("consent-given", "true"); // Mark consent as given/handled
        localStorage.setItem("consent-preferences", JSON.stringify({
            encryptedData: arrayBufferToBase64(encryptedPreferencesBuffer), // Store encrypted data as base64
            iv: Array.from(ivBytes), // Store IV as array of numbers
            key: Array.from(keyArray) // Store key as array of numbers
        }));
  
        // Store metadata separately for easier access if needed (optional)
        localStorage.setItem("consent-policy-version", consentPreferencesToStore.consentPolicyVersion);
        localStorage.setItem("consent-timestamp", consentPreferencesToStore.consentTimestamp);
  
        console.log("Encrypted consent preferences saved to localStorage.");
        // Update global state after successful save
        consentState = consentPreferencesToStore;
  
    } catch (error) {
        console.error("Error encrypting or saving consent to localStorage:", error);
    }
  }
  // --- END MODIFIED ---\n\n// --- REMOVED: buildPayload function (Payload built directly in saveConsentState) ---
  /*
  function buildPayload({ clientId, encryptedVisitorId, encryptedPreferences, encryptionKey, policyVersion, timestamp, country }) {
      // ... removed ...
  }
  */
  // --- END REMOVED ---
  
  
  /*CONSENT  SAVING TO LOCALSTORAGE AND SERVER ENDS*/
  
  
  /*Blocking and unblocking */
  function getScriptKey(script) {
      // Use src if available (normalized), otherwise try to hash content for a key
      if (script.src) {
          return normalizeUrl(script.src); // Use normalized URL as key
      } else if (script.textContent) {
           // Simple key from content length + first/last few chars (avoid hashing full content)
           const content = script.textContent.trim();
           if (!content) return null; // Cannot key empty inline script
           return `inline_${content.length}_${content.slice(0,15)}_${content.slice(-15)}`;
      }
      return null; // Should not happen for valid scripts
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
      if (!content) return null;
      const cleaned = content.replace(/\s+/g, ""); // Remove whitespace for matching
      for (const { pattern, category } of suspiciousPatterns) {
        if (pattern.test(cleaned)) {
          return category;
        }
      }
      return null;
    }
  
  // --- MODIFIED: isScriptAlreadyBlocked uses the global existing_Scripts object by ID ---
  function isScriptAlreadyBlocked(script) {
      // Check if a placeholder for this script exists (identified by data-consentbit-id)
      if (script.hasAttribute('data-consentbit-id')) {
          return true; // It's one of our placeholders
      }
  
      // Check if the script element itself is of type 'text/plain'
      if (script.type === 'text/plain') {
           // Check if it has our ID attribute - if so, it's blocked
           if (script.hasAttribute('data-consentbit-id')) {
               return true;
           }
           // If it's text/plain but doesn't have our ID, treat as not blocked *by us*
           return false;
      }
  
  
      // More robust check: Use getScriptKey and see if a script with that key exists in our map
      const key = getScriptKey(script);
      if (!key) return false; // Cannot determine blocking status without a key
  
      return Object.values(existing_Scripts).some(info => info.key === key);
  }
  // --- END MODIFIED ---
  
  // --- REFACTORED: checkAndBlockNewScripts simplified, acts as a trigger/check ---
  async function checkAndBlockNewScripts() {
       // This function ensures blocking/observer state matches current consent.
       // It's useful after consent changes where `restoreAllowedScripts` might not have run
       // or if dynamically loaded scripts need checking against current rules.
       console.log("Checking if script blocking/observer needs update...");
       const prefs = await _getDecryptedPreferences();
       const needsBlocking = !prefs || // No consent yet OR needs blocking based on prefs
                            prefs.Marketing === false ||
                            prefs.Personalization === false ||
                            prefs.Analytics === false ||
                            prefs.ccpa?.DoNotShare === true; // Check correct property
  
       if (needsBlocking) {
           // Ensure the observer is running to catch future scripts
           if (!observer) {
                console.log("Blocking is needed, ensuring observer is active via scanAndBlockScripts.");
                await scanAndBlockScripts(); // This will setup observer if needed
           } else {
                // console.log("Blocking is needed, observer already active.");
           }
           // Optionally, re-scan existing scripts that might have been missed or added before observer was active
           // This depends on whether scanAndBlockScripts handles already-loaded scripts correctly.
           // await scanAndBlockScripts(); // Re-running might be safe if it checks `isScriptAlreadyBlocked`
       } else {
            // Ensure observer is stopped if not needed
            if (observer) {
                 observer.disconnect();
                 observer = null;
                 console.log("Observer stopped by checkAndBlockNewScripts as blocking is no longer needed.");
            } else {
                 // console.log("Blocking not needed, observer already inactive.");
            }
       }
  }
  // --- END REFACTORED ---
  
  
  function normalizeUrl(url) {
      if (!url) return null;
      try {
         // Use URL constructor for more robust parsing and normalization
         const urlObj = new URL(url, window.location.origin); // Provide base if URL is relative
         // Normalize by removing protocol, www, trailing slash, and query params/hash
         let normalized = urlObj.hostname.replace(/^www\./, '') + urlObj.pathname;
         normalized = normalized.replace(/\/$/, ''); // Remove trailing slash
         return normalized;
      } catch (e) {
         // Fallback for invalid URLs or simple strings
         return url.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/$/, '');
      }
  }
  
  function createPlaceholder(originalScript, category = "uncategorized") {
    const placeholder = document.createElement("script");
    const uniqueId = `consentbit-script-${scriptIdCounter++}`; // Generate a unique ID
    const scriptKey = getScriptKey(originalScript); // Get the key
  
    if (!scriptKey) {
         console.warn("Cannot create placeholder for script without a key:", originalScript);
         return null; // Cannot track without a key
    }
  
    // Check if already blocked by key to prevent duplicate placeholders
    if (Object.values(existing_Scripts).some(info => info.key === scriptKey)) {
        console.log(`Script with key ${scriptKey} already blocked. Skipping placeholder creation.`);
        // Optionally remove the original script node here if it wasn't replaced yet
        if (originalScript.parentNode) {
             originalScript.parentNode.removeChild(originalScript);
        }
        return null;
    }
  
    placeholder.type = "text/plain"; // Keep it non-executable
    placeholder.setAttribute("data-consentbit-id", uniqueId);
    placeholder.setAttribute("data-category", category.toLowerCase()); // Store lowercase
    if (originalScript.src) {
         placeholder.setAttribute("data-original-src", originalScript.src); // Keep for reference
    }
    // Copy original text content to placeholder? Maybe not necessary, store in scriptInfo.
    // placeholder.textContent = ` ConsentBit blocked script: ${originalScript.src || 'inline script'} `;
  
  
    const scriptInfo = {
        id: uniqueId,
        key: scriptKey, // Store the key used for blocking/duplicate checks
        category: category.split(',').map(c => c.trim().toLowerCase()), // Store categories as lowercase array
        async: originalScript.async,
        defer: originalScript.defer,
        type: originalScript.type || "text/javascript", // Default type if missing
        originalAttributes: {}
    };
  
    // Store original src or content
    if (originalScript.src) {
        scriptInfo.src = originalScript.src;
    } else {
        scriptInfo.content = originalScript.textContent || "";
    }
  
    // Store other relevant attributes
    for (const attr of originalScript.attributes) {
        // Exclude attributes we manage or derive
        const lowerCaseAttrName = attr.name.toLowerCase();
        if (!['src', 'type', 'async', 'defer', 'data-category', 'data-consentbit-id', 'data-original-src'].includes(lowerCaseAttrName)) {
            scriptInfo.originalAttributes[attr.name] = attr.value;
            // Optional: keep original attrs on placeholder
            // placeholder.setAttribute(`data-original-${attr.name}`, attr.value);
        }
    }
  
    // Add script info to our map, keyed by the unique ID
    existing_Scripts[uniqueId] = scriptInfo;
    // console.log(`Created placeholder ${uniqueId} for script: ${scriptKey}`);
  
    return placeholder;
  }
  
  function findCategoryByPattern(text) {
      if (!text) return null;
      const cleanedText = text.replace(/\s+/g, ""); // Clean text for matching
      for (const { pattern, category } of suspiciousPatterns) {
          if (pattern.test(cleanedText)) { // Test against cleaned text
              // console.log(`Pattern matched for category ${category}:`, pattern);
              return category;
          }
      }
      // console.log(`No pattern matched for text (cleaned): ${cleanedText.substring(0, 100)}...`);
      return null;
  }
  
  
  async function loadCategorizedScripts() {
          console.log("Attempting to load categorized scripts from server...");
          try {
              const sessionToken = localStorage.getItem('visitorSessionToken');
              if (!sessionToken || isTokenExpired(sessionToken)) {
                  if(!sessionToken) console.error('No session token found. Cannot load categorized scripts.');
                  if(sessionToken && isTokenExpired(sessionToken)) console.error('Session token expired. Cannot load categorized scripts.');
                  return [];
              }
  
              const visitorId = await getOrCreateVisitorId();
              const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
  
              // Generate encryption key and IV for the request
              const { key: requestKey, iv: requestIv } = await EncryptionUtils.generateKey();
              const requestIvBytes = new Uint8Array(requestIv);
  
              // Prepare request data
              const requestData = { siteName, visitorId, userAgent: navigator.userAgent };
  
              // Encrypt the request data
              const encryptedRequestBuffer = await EncryptionUtils.encrypt(JSON.stringify(requestData), requestKey, requestIvBytes);
              const b64EncryptedRequest = arrayBufferToBase64(encryptedRequestBuffer);
  
              // Export key for sending
              const rawRequestKey = await crypto.subtle.exportKey('raw', requestKey);
              const requestKeyArray = new Uint8Array(32);
              requestKeyArray.set(new Uint8Array(rawRequestKey).slice(0, 32));
              const b64RequestKey = arrayBufferToBase64(requestKeyArray.buffer);
              const b64RequestIV = arrayBufferToBase64(requestIvBytes.buffer);
  
              // Send the encrypted request
              const apiUrl = 'https://cb-server.web-8fb.workers.dev/api/cmp/script-category';
              console.log("Fetching script categories from:", apiUrl);
              const response = await fetch(apiUrl, {
                  method: 'POST',
                  headers: {
                      'Authorization': `Bearer ${sessionToken}`,
                      'X-Request-ID': crypto.randomUUID(),
                      'Content-Type': 'application/json',
                      'Accept': 'application/json',
                  },
                  body: JSON.stringify({
                      encryptedData: b64EncryptedRequest,
                      key: b64RequestKey, // Send as base64 string
                      iv: b64RequestIV   // Send as base64 string
                  }),
                  mode: 'cors'
              });
  
              if (!response.ok) {
                  const errorText = await response.text();
                  console.error(`Failed to load categorized scripts (${response.status}): ${errorText}`);
                  return [];
              }
  
              const data = await response.json();
  
              // Decrypt the response data (if encrypted)
              if (data.encryptedData && data.key && data.iv) {
                   console.log("Decrypting categorized scripts response...");
                  try {
                      // Import key sent by server (assuming it's base64)
                       const responseKeyBytes = base64ToArrayBuffer(data.key);
                       const responseIvBytes = base64ToArrayBuffer(data.iv);
  
                       if (responseKeyBytes.byteLength !== 32 || responseIvBytes.byteLength !== 12) {
                            console.error(`Invalid key (${responseKeyBytes.byteLength}) or IV (${responseIvBytes.byteLength}) length from server.`);
                            return [];
                       }
  
                      const responseKey = await EncryptionUtils.importKey(
                          new Uint8Array(responseKeyBytes), // Import key from ArrayBuffer
                          ['decrypt']
                      );
  
                      const decryptedData = await EncryptionUtils.decrypt(
                          data.encryptedData, // Decrypt base64 data
                          responseKey,
                          new Uint8Array(responseIvBytes) // Use IV from ArrayBuffer
                      );
  
                      const responseObj = JSON.parse(decryptedData);
                      // Ensure scripts property is an array
                      categorizedScripts = Array.isArray(responseObj.scripts) ? responseObj.scripts : [];
                      console.log(`Successfully loaded and decrypted ${categorizedScripts.length} categorized scripts.`);
                      return categorizedScripts;
                  } catch (decryptionError) {
                       console.error("Error decrypting script category response:", decryptionError);
                       return [];
                  }
              } else if (Array.isArray(data.scripts)) {
                   // Handle non-encrypted response containing a scripts array
                   console.log(`Successfully loaded ${data.scripts.length} non-encrypted categorized scripts.`);
                   categorizedScripts = data.scripts;
                   return categorizedScripts;
              }
               else {
                   console.warn("Received response for categorized scripts, but data format was unexpected:", data);
                  return []; // Return empty if format is wrong
              }
          } catch (error) {
               console.error("Network or other error loading categorized scripts:", error);
              return []; // Return empty on error
          }
        }
  
  
      // --- REFACTORED: scanAndBlockScripts includes observer setup and handles existing/new scripts ---
  async function scanAndBlockScripts() {
      console.log("Scanning for scripts to block...");
  
      // 1. Load server-side categories if not already cached
      // Use cached list if available, otherwise fetch
      const categorizedScriptsList = categorizedScripts || await loadCategorizedScripts();
  
      // Prepare a map for faster lookup (normalizedSrc -> categories)
      const serverCategoriesMap = new Map();
      categorizedScriptsList.forEach(s => {
          const categories = Array.isArray(s.category)
              ? s.category.map(c => String(c).trim().toLowerCase())
              : (String(s.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean));
          if (s.src) {
              const normalizedSrc = normalizeUrl(s.src);
              if (normalizedSrc) serverCategoriesMap.set(normalizedSrc, categories);
          }
          // Note: Matching inline scripts reliably by content from server is hard. Focus on src.
      });
      console.log(`Using ${serverCategoriesMap.size} server-categorized scripts.`);
  
  
      // 2. Find all *potentially executable* script elements in the DOM
      // Exclude placeholders (type='text/plain' AND has data-consentbit-id)
      // Exclude scripts already processed (has data-consentbit-id on the *placeholder*)
      const scriptsToCheck = Array.from(document.querySelectorAll("script:not([type='text/plain']):not([data-consentbit-id]), script[type='text/plain']:not([data-consentbit-id])"));
      console.log(`Found ${scriptsToCheck.length} script elements to check for blocking.`);
  
  
      // 3. Process Scripts
      scriptsToCheck.forEach(script => {
           // Skip if it's a placeholder we somehow missed querying
           if (script.type === 'text/plain' && script.hasAttribute('data-consentbit-id')) return;
           // Skip if it's already blocked (check our map by key)
          if (isScriptAlreadyBlocked(script)) return;
  
          const scriptKey = getScriptKey(script);
          if (!scriptKey) return; // Cannot process without a key
  
          let scriptCategories = [];
          let categorySource = 'none';
  
          // Determine category
          if (script.src) {
              const normalizedSrc = normalizeUrl(script.src);
              if (serverCategoriesMap.has(normalizedSrc)) {
                  scriptCategories = serverCategoriesMap.get(normalizedSrc);
                  categorySource = 'server';
              } else {
                  const patternCategory = findCategoryByPattern(script.src);
                  if (patternCategory) {
                      scriptCategories = [patternCategory.toLowerCase()];
                      categorySource = 'pattern (src)';
                  }
              }
          } else if (script.textContent) {
               // Try pattern matching for inline scripts
               const patternCategory = findCategoryByPattern(script.textContent);
               if (patternCategory) {
                   scriptCategories = [patternCategory.toLowerCase()];
                   categorySource = 'pattern (inline)';
               }
          }
  
          // Block if categorized
          if (scriptCategories.length > 0) {
              console.log(`Blocking script (${categorySource}): ${scriptKey}, Categories: ${scriptCategories.join(',')}`);
              _blockSingleScriptNode(script, scriptCategories); // This handles placeholder creation and map update
          } else {
              // console.log(`Script not blocked (no category found): ${scriptKey}`);
               // If script is type='text/plain' but has no category and no consentbit ID,
               // it *might* be intended to be blocked by another mechanism, or is data. Leave it.
               if(script.type !== 'text/plain') {
                   console.log(`Script type='${script.type || 'text/javascript'}' not blocked (no category): ${scriptKey}`);
               }
          }
      });
  
      // 4. Setup/Update MutationObserver based on current consent
      // This ensures dynamically added scripts are handled correctly
      await _updateObserverState();
  
      console.log("Script scanning and blocking finished.");
  }
  // --- END REFACTORED ---
  
  // +++ ADDED: Helper function to manage observer state +++
  async function _updateObserverState() {
       const prefs = await _getDecryptedPreferences();
       const needsBlocking = !prefs || prefs.Marketing === false || prefs.Personalization === false || prefs.Analytics === false || prefs.ccpa?.DoNotShare === true; // Use correct property
  
       if (needsBlocking && !observer) {
           // Need blocking, observer not active: SETUP OBSERVER
           console.log("Setting up MutationObserver...");
  
           // Load categories again here? Or assume list used by scanAndBlockScripts is sufficient?
           // Re-fetch might be safer if list could change. For now, assume list is static enough.
           const categorizedScriptsList = categorizedScripts || []; // Use cached
            const serverCategoriesMap = new Map();
              categorizedScriptsList.forEach(s => {
                  const categories = Array.isArray(s.category)
                      ? s.category.map(c => String(c).trim().toLowerCase())
                      : (String(s.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean));
                  if (s.src) {
                      const normalizedSrc = normalizeUrl(s.src);
                      if (normalizedSrc) serverCategoriesMap.set(normalizedSrc, categories);
                  }
              });
  
           observer = new MutationObserver((mutationsList) => {
               // Check consent *inside* the callback *before* blocking new nodes
               _getDecryptedPreferences().then(currentPrefs => {
                   const blockingStillNeeded = !currentPrefs || currentPrefs.Marketing === false || currentPrefs.Personalization === false || currentPrefs.Analytics === false || currentPrefs.ccpa?.DoNotShare === true;
  
                   if (!blockingStillNeeded) {
                       if (observer) { // Check again in case it was disconnected concurrently
                           observer.disconnect();
                           observer = null;
                           console.log("MutationObserver disconnected automatically as blocking is no longer needed.");
                       }
                       return;
                   }
  
                   // Blocking is needed, process mutations
                   for (const mutation of mutationsList) {
                      for (const node of mutation.addedNodes) {
                          if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'SCRIPT') {
                              // Check if it's executable and not already handled/blocked
                              if (node.type !== 'text/plain' && !node.hasAttribute('data-consentbit-id') && !isScriptAlreadyBlocked(node)) {
  
                                  const nodeKey = getScriptKey(node);
                                  if (!nodeKey) continue;
  
                                  let nodeCategories = [];
                                  let nodeCatSource = 'none';
  
                                  if (node.src) {
                                      const normalizedSrc = normalizeUrl(node.src);
                                      if (serverCategoriesMap.has(normalizedSrc)) {
                                          nodeCategories = serverCategoriesMap.get(normalizedSrc);
                                          nodeCatSource = 'server';
                                      } else {
                                          const patternCat = findCategoryByPattern(node.src);
                                          if (patternCat) { nodeCategories = [patternCat.toLowerCase()]; nodeCatSource = 'pattern (src)'; }
                                      }
                                  } else if (node.textContent) {
                                       const patternCat = findCategoryByPattern(node.textContent);
                                       if (patternCat) { nodeCategories = [patternCat.toLowerCase()]; nodeCatSource = 'pattern (inline)'; }
                                  }
  
                                  if (nodeCategories.length > 0) {
                                      console.log(`Observer blocking dynamically added script (${nodeCatSource}): ${nodeKey}, Categories: ${nodeCategories.join(',')}`);
                                       _blockSingleScriptNode(node, nodeCategories); // Block it
                                  } else {
                                       // console.log(`Observer: Script not blocked (no category): ${nodeKey}`);
                                  }
                              }
                          }
                      }
                  }
              }).catch(err => console.error("Error checking prefs in observer:", err));
           });
  
           observer.observe(document.documentElement, { childList: true, subtree: true });
           console.log("MutationObserver activated.");
  
       } else if (!needsBlocking && observer) {
            // Blocking not needed, observer is active: DISCONNECT OBSERVER
            observer.disconnect();
            observer = null;
            console.log("MutationObserver disconnected as blocking is not currently needed.");
       } else {
           // State matches (Needs blocking & observer active OR Not needed & observer inactive)
           // console.log(`Observer state matches requirement (Needs Blocking: ${needsBlocking}, Observer Active: ${!!observer})`);
       }
  }
  // +++ END ADDED HELPER +++
  
  
  // --- Renamed: _blockScriptNode to _blockSingleScriptNode for clarity ---
  /** Helper to block a single script node */
  function _blockSingleScriptNode(scriptNode, categories) {
      // Double-check if already blocked (using map check is more reliable now)
      if (isScriptAlreadyBlocked(scriptNode)) {
           // console.log(`Script ${getScriptKey(scriptNode)} already handled/blocked. Skipping.`);
           return;
      }
  
      const placeholder = createPlaceholder(scriptNode, categories.join(','));
      if (placeholder && scriptNode.parentNode && document.contains(scriptNode)) {
           try {
                scriptNode.parentNode.replaceChild(placeholder, scriptNode);
                // console.log(`Blocked script node: ${placeholder.getAttribute('data-consentbit-id')}`);
           } catch (error) {
                console.error(`Error replacing script node ${getScriptKey(scriptNode)} with placeholder:`, error);
           }
      } else if (placeholder && !scriptNode.parentNode) {
           // Script might be detached or not yet in DOM fully
           console.warn(`Script node ${getScriptKey(scriptNode)} has no parent during blocking attempt.`);
      } else if (placeholder && !document.contains(scriptNode)) {
           console.warn(`Script node ${getScriptKey(scriptNode)} was removed from DOM before it could be blocked.`);
      } else if (!placeholder) {
           // createPlaceholder failed (likely due to duplicate key check)
      }
  }
  // --- END Renamed ---
  
  
  async function acceptAllCookies() {
      console.log("Accepting all cookies...");
      const allAllowedPreferences = {
          Necessary: true,
          Marketing: true,
          Personalization: true,
          Analytics: true,
          ccpa: { DoNotShare: false } // Accepting all implies DoNotShare is false
      };
  
      await saveConsentState(allAllowedPreferences); // Saves locally, updates global state, tries server save
  
      // --- MODIFIED: Update UI form ---
      await updatePreferenceForm(allAllowedPreferences);
      // --- END MODIFIED ---
  
      await restoreAllowedScripts(allAllowedPreferences); // Unblocks scripts
  
      // --- MODIFIED: Ensure observer is stopped ---
      await _updateObserverState(); // This should detect no blocking needed and stop observer
      // --- END MODIFIED ---
  
      // Hide all banners
      hideBanner(document.getElementById("consent-banner"));
      hideBanner(document.getElementById("initial-consent-banner"));
      hideBanner(document.getElementById("main-banner"));
      hideBanner(document.getElementById("main-consent-banner"));
      hideBanner(document.getElementById("simple-consent-banner"));
  
      // localStorage.setItem("consent-given", "true"); // Already set in saveConsentState/storeEncryptedConsentLocally
  }
  // Make sure it's globally accessible
  window.acceptAllCookies = acceptAllCookies;
  
  async function blockAllCookies() {
    console.log("Blocking all non-necessary cookies...");
    const rejectNonNecessaryPreferences = {
        Necessary: true,
        Marketing: false,
        Personalization: false,
        Analytics: false,
        ccpa: { DoNotShare: true } // Blocking all non-essential implies DoNotShare = true
    };
  
    await saveConsentState(rejectNonNecessaryPreferences); // Saves locally, updates global state, tries server save
  
    // --- MODIFIED: Update UI form ---
    await updatePreferenceForm(rejectNonNecessaryPreferences);
    // --- END MODIFIED ---
  
    await restoreAllowedScripts(rejectNonNecessaryPreferences); // Restores only necessary
  
    // --- MODIFIED: Ensure observer is active ---
    await _updateObserverState(); // This should detect blocking needed and start observer
    // --- END MODIFIED ---
  
  
    // Hide all banners
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner"));
    hideBanner(document.getElementById("main-banner"));
    hideBanner(document.getElementById("main-consent-banner"));
    hideBanner(document.getElementById("simple-consent-banner"));
  
    // localStorage.setItem("consent-given", "true"); // Already set
  }
  // Make sure it's globally accessible
  window.blockAllCookies = blockAllCookies;
  
  // --- REMOVED: Duplicate global assignments ---
  // window.blockAllCookies=blockAllCookies;
  // window.acceptAllCookies=acceptAllCookies;
  // --- END REMOVED ---
  
    /*CONSENT STATE LOADING AND UI UPDATE */
  
  async function _getDecryptedPreferences() {
        // console.log("Attempting to load and decrypt preferences from localStorage...");
        try {
            const savedPreferencesRaw = localStorage.getItem("consent-preferences");
            const consentGiven = localStorage.getItem("consent-given") === "true";
  
            if (!savedPreferencesRaw || !consentGiven) {
                // console.log("No valid consent found in localStorage.");
                localStorage.removeItem("consent-preferences");
                localStorage.removeItem("consent-given");
                return null;
            }
  
            const savedPreferences = JSON.parse(savedPreferencesRaw);
            if (!savedPreferences?.encryptedData || !savedPreferences.key || !savedPreferences.iv) {
                 console.warn("Stored preferences format is invalid.");
                 localStorage.removeItem("consent-preferences");
                 localStorage.removeItem("consent-given");
                 return null;
            }
  
            const keyBytes = new Uint8Array(savedPreferences.key);
            if (keyBytes.length !== 32) {
                console.error(`Invalid key length (${keyBytes.length}) in stored preferences. Expected 32.`);
                localStorage.removeItem("consent-preferences");
                localStorage.removeItem("consent-given");
                return null;
            }
  
            const ivBytes = new Uint8Array(savedPreferences.iv);
            if (ivBytes.length !== 12) {
                 console.error(`Invalid IV length (${ivBytes.length}) in stored preferences. Expected 12.`);
                 localStorage.removeItem("consent-preferences");
                 localStorage.removeItem("consent-given");
                 return null;
            }
  
            const key = await EncryptionUtils.importKey(
                 keyBytes, // Pass Uint8Array directly
                 ['decrypt']
             );
  
            const decryptedString = await EncryptionUtils.decrypt(
                savedPreferences.encryptedData, // Pass base64 string directly
                key,
                ivBytes // Pass Uint8Array directly
            );
  
            // console.log("Successfully decrypted preferences.");
            const decryptedPrefs = JSON.parse(decryptedString);
            // Add validation for the structure of decryptedPrefs if needed
            if (typeof decryptedPrefs !== 'object' || decryptedPrefs === null) {
                 throw new Error("Decrypted preferences are not a valid object.");
            }
            return decryptedPrefs;
  
        } catch (error) {
            console.error("Failed to load or decrypt preferences:", error);
            localStorage.removeItem("consent-preferences");
            localStorage.removeItem("consent-given");
            return null;
        }
  }
  // --- END MODIFIED ---
  
    /**
     * Updates the consent form checkboxes based on the provided state.
     * @param {object} state The consent state object.
     */
    // --- RENAMED: _updateConsentCheckboxes to updatePreferenceForm ---
    // --- Made async as it might be called directly ---
  async function updatePreferenceForm(state) {
        if (!state || typeof state !== 'object') { // Add type check
             console.warn("updatePreferenceForm called with invalid state:", state);
             return;
        }
        // console.log("Updating preference form UI with state:", state);
  
        // Normalize state for consistent access
        const prefs = {
            Necessary: true, // Always true
            Marketing: state.Marketing ?? false,
            Personalization: state.Personalization ?? false,
            Analytics: state.Analytics ?? false,
            // Handle potential variations in how DoNotShare is stored
            DoNotShare: state.ccpa?.DoNotShare ?? state.DoNotShare ?? false
        };
  
        // Helper to update a checkbox
        const updateCheckbox = (selector, isChecked) => {
            const checkbox = document.querySelector(selector);
            if (checkbox) {
                checkbox.checked = isChecked;
            } else {
                // console.warn(`Checkbox not found: ${selector}`);
            }
        };
  
        // Update GDPR Form Checkboxes (scoped to #main-banner)
        const necessaryGdpr = document.querySelector('#main-banner [data-consent-id="necessary-checkbox"]');
        if (necessaryGdpr) {
            necessaryGdpr.checked = true;
            necessaryGdpr.disabled = true;
        }
        updateCheckbox('#main-banner [data-consent-id="marketing-checkbox"]', prefs.Marketing);
        updateCheckbox('#main-banner [data-consent-id="personalization-checkbox"]', prefs.Personalization);
        updateCheckbox('#main-banner [data-consent-id="analytics-checkbox"]', prefs.Analytics);
  
        // Update CCPA Form Checkbox (scoped to #main-consent-banner)
        updateCheckbox('#main-consent-banner [data-consent-id="do-not-share-checkbox"]', prefs.DoNotShare);
  
         // console.log("Preference form UI updated.");
  }
  // --- END RENAMED ---
  
  
  
  // --- REMOVED: _setupConsentAwareTool (integrated into _restoreSingleScript) ---
  
  
  // --- MODIFIED: _restoreSingleScript to integrate tool consent updates ---
  function _restoreSingleScript(scriptId, scriptInfo, normalizedPrefs) {
      if (!scriptInfo || !scriptInfo.key) { // Need key
          console.warn(`Invalid scriptInfo provided to _restoreSingleScript for ID: ${scriptId}`);
          if (scriptId && existing_Scripts[scriptId]) delete existing_Scripts[scriptId]; // Clean up map if ID exists
          return;
      }
  
      const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
      if (!placeholder) {
          // console.warn(`Placeholder not found for scriptId ${scriptId}. Cleaning up map entry.`);
          delete existing_Scripts[scriptId];
          return;
      }
  
      const script = document.createElement("script");
  
      // Restore core properties
      script.type = scriptInfo.type || "text/javascript"; // Default to JS
      if (scriptInfo.async) script.async = true;
      if (scriptInfo.defer) script.defer = true;
  
      // Restore category attribute
      const categories = scriptInfo.category || []; // Already lowercase array
      script.setAttribute("data-category", categories.join(','));
  
      // Restore other original attributes
      if (scriptInfo.originalAttributes) {
          Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
              // Avoid setting potentially harmful attributes like integrity if content changed?
              // For now, restore all non-managed attributes.
              script.setAttribute(name, value);
          });
      }
  
      // --- ADDED: Set textContent *before* appending for inline scripts ---
      if (!scriptInfo.src && scriptInfo.content) {
           script.textContent = scriptInfo.content;
      }
      // --- END ADDED ---
  
      // Replace placeholder with actual script *before* setting src for external scripts
      // This ensures the script element is in the DOM in the correct position
      let insertionPoint = placeholder.parentNode;
      let replaced = false;
      if (insertionPoint && document.contains(placeholder)) {
          try {
              insertionPoint.replaceChild(script, placeholder);
              replaced = true;
               // console.log(`Restored script: ${scriptInfo.key}`);
          } catch (replaceError) {
              console.error(`Error replacing placeholder for scriptId ${scriptId}:`, replaceError);
              // Fallback: try appending to head
               try {
                   document.head.appendChild(script);
                   replaced = true; // Consider it placed
                   console.warn(`Appended script ${scriptId} to head as fallback after replacement error.`);
               } catch (appendError) {
                    console.error(`Error appending script ${scriptId} to head as fallback:`, appendError);
               }
          }
      } else {
           console.warn(`Placeholder or parentNode missing for scriptId ${scriptId}. Appending to head.`);
           try {
               document.head.appendChild(script);
               replaced = true; // Consider it placed
           } catch (appendError) {
                console.error(`Error appending script ${scriptId} to head as fallback:`, appendError);
           }
      }
  
  
      // If successfully placed in DOM, set src (for external) and update tool consent
      if (replaced) {
          if (scriptInfo.src) {
              // Set src *after* inserting the element
              script.src = scriptInfo.src;
              _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs);
          } else {
               // For inline scripts, tool consent might need different handling if needed
               _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs); // Still call, handler might work based on content patterns
          }
      } else {
           console.error(`Failed to place script ${scriptId} in DOM. Cannot set src or update tools.`);
      }
  
  
      // Clean up the entry from our tracking object regardless of DOM insertion success?
      // If insertion failed, maybe keep it? For now, remove it as we tried.
      delete existing_Scripts[scriptId];
  }
  // --- END MODIFIED ---
  
  // --- REMOVED: unblockAllCookiesAndTools (Functionality covered by acceptAllCookies) ---
  
  
  /** Helper Functions for restoreAllowedScripts **/
  
  function _isScriptAllowed(categories, normalizedPrefs) {
      if (!Array.isArray(categories) || !normalizedPrefs) {
          console.warn("Invalid input to _isScriptAllowed:", categories, normalizedPrefs);
          return false;
      }
      // 'necessary' category is always allowed
      if (categories.includes('necessary')) return true;
  
      // Check CCPA DoNotShare first
      if (normalizedPrefs.ccpa?.donotshare === true) { // Use normalized key
          // If DoNotShare is true, deny Marketing, Personalization, Analytics
          if (categories.includes('marketing') || categories.includes('personalization') || categories.includes('analytics')) {
              // console.log(`Script denied due to CCPA DoNotShare. Categories: ${categories.join(',')}`);
              return false;
          }
      }
  
      // Otherwise, check explicit preferences for remaining categories
      const isAllowed = categories.some(cat => normalizedPrefs[cat.toLowerCase()] === true);
      // if (!isAllowed && categories.length > 0 && !categories.includes('necessary')) {
      //      console.log(`Script denied by explicit prefs. Categories: ${categories.join(',')}, Prefs: ${JSON.stringify(normalizedPrefs)}`);
      // }
      return isAllowed;
  }
  
  
  /** Individual Tool Consent Update Handlers **/
  
  function _handleGtagConsentUpdate(script, normalizedPrefs) {
      const settings = _getGtagConsentSettings(normalizedPrefs);
      // Ensure gtag command queue exists
      window.dataLayer = window.dataLayer || [];
      window.gtag = window.gtag || function(){dataLayer.push(arguments);};
  
      console.log("Updating gtag consent:", settings);
      gtag('consent', 'update', settings);
  
      // Add onload handler for scripts that load gtag itself? Might be too late.
      // If script *is* the gtag loader:
      if (script.src && /googletagmanager\.com\/gtag\/js/.test(script.src)) {
           script.onload = () => {
                console.log("gtag.js loaded, ensuring consent update is applied.");
                // Re-apply consent just in case gtag wasn't ready before
                // This might be redundant if gtag processes queue on load
                 window.gtag = window.gtag || function(){dataLayer.push(arguments);};
                 gtag('consent', 'update', settings);
           };
           script.onerror = () => console.error(`Failed to load gtag.js script: ${script.src}`);
      }
  }
  
  // Helper to generate gtag settings object
  function _getGtagConsentSettings(normalizedPrefs) {
       const settings = {
          'ad_storage': normalizedPrefs.marketing ? 'granted' : 'denied',
          'analytics_storage': normalizedPrefs.analytics ? 'granted' : 'denied',
          'personalization_storage': normalizedPrefs.personalization ? 'granted' : 'denied', // v2 param
          'functionality_storage': 'granted', // Usually necessary
          'security_storage': 'granted',      // Usually necessary
          'ad_user_data': normalizedPrefs.marketing ? 'granted' : 'denied',
          'ad_personalization': normalizedPrefs.marketing ? 'granted' : 'denied'
          // 'wait_for_update': 500 // Optional: Max time (ms) to wait for update
      };
      return settings;
  }
  
  function _handleAmplitudeConsentUpdate(script, normalizedPrefs) {
      const analyticsAllowed = normalizedPrefs.analytics === true;
      const userProperties = {
          consent_analytics: normalizedPrefs.analytics,
          consent_marketing: normalizedPrefs.marketing,
          consent_personalization: normalizedPrefs.personalization ?? false // Use nullish coalescing
      };
  
      const updateConsent = () => {
          if (typeof amplitude !== "undefined" && amplitude.getInstance) {
              try {
                  console.log(`Updating Amplitude consent: OptOut=${!analyticsAllowed}, UserProps=${JSON.stringify(userProperties)}`);
                  const instance = amplitude.getInstance();
                  instance.setOptOut(!analyticsAllowed);
                  instance.setUserProperties(userProperties);
              } catch (error) { console.error("Error setting Amplitude consent:", error); }
          } else {
               console.warn("Amplitude instance not found for consent update.");
          }
      };
  
      // If the script being restored *is* the Amplitude loader, wait for onload
      if (script.src && /cdn\.(eu\.)?amplitude\.com/.test(script.src)) {
          script.onload = () => {
               console.log("Amplitude script loaded, attempting consent update.");
               setTimeout(updateConsent, 100); // Small delay after load
          };
          script.onerror = () => console.error(`Failed to load Amplitude script: ${script.src}`);
      } else {
           // If Amplitude might already be loaded, try immediately
           setTimeout(updateConsent, 0);
      }
  }
  
  
  function _handleClarityConsentUpdate(normalizedPrefs) {
       console.log(`Updating Clarity consent: ${normalizedPrefs.analytics === true}`);
      window.clarity = window.clarity || function(...args) { (window.clarity.q = window.clarity.q || []).push(args); };
      // Clarity reads this flag on initialization
      window.clarity.consent = normalizedPrefs.analytics === true;
      // No explicit update command documented, relies on flag before init.
  }
  
  function _handleFacebookPixelConsentUpdate(script, normalizedPrefs) {
      const granted = normalizedPrefs.marketing === true;
      window.fbq = window.fbq || function(){fbq.callMethod?fbq.callMethod.apply(fbq,arguments):fbq.queue.push(arguments)};
      window.fbq.queue = window.fbq.queue || [];
  
      console.log(`Updating Facebook Pixel consent: ${granted ? 'grant' : 'revoke'}`);
      fbq('consent', granted ? 'grant' : 'revoke');
  
       if (script.src && /connect\.facebook\.net/.test(script.src)) {
            script.onload = () => {
                 console.log("Facebook Pixel script loaded, ensuring consent update is applied.");
                  window.fbq = window.fbq || function(){fbq.callMethod?fbq.callMethod.apply(fbq,arguments):fbq.queue.push(arguments)};
                  window.fbq.queue = window.fbq.queue || [];
                  fbq('consent', granted ? 'grant' : 'revoke');
            };
            script.onerror = () => console.error(`Failed to load Facebook Pixel script: ${script.src}`);
       }
  }
  
  
  function _handleMatomoConsentUpdate(script, normalizedPrefs) {
      const granted = normalizedPrefs.analytics === true;
      window._paq = window._paq || []; // Ensure queue exists
  
      if (granted) {
          console.log("Granting Matomo consent.");
          _paq.push(['setConsentGiven']);
          // Clear any previous requirement? Check Matomo docs.
          // _paq.push(['forgetTrackingsConsent']);
      } else {
          console.log("Revoking Matomo consent.");
          _paq.push(['forgetConsentGiven']);
          // Ensure tracking requires consent if not already set globally
          // _paq.push(['requireConsent']);
      }
  
       if (script.src && /matomo\.cloud/.test(script.src)) {
            script.onload = () => {
                 console.log("Matomo script loaded, ensuring consent update applied.");
                 window._paq = window._paq || [];
                 if(granted) _paq.push(['setConsentGiven']); else _paq.push(['forgetConsentGiven']);
            };
             script.onerror = () => console.error(`Failed to load Matomo script: ${script.src}`);
       }
  }
  
  
  function _handleHubSpotConsentUpdate(script, normalizedPrefs) {
      const granted = normalizedPrefs.marketing === true || normalizedPrefs.personalization === true;
      window._hsq = window._hsq || []; // Ensure queue exists
  
      console.log(`Updating HubSpot consent (doNotTrack): ${!granted}`);
      _hsq.push(['doNotTrack', !granted]); // True means do not track
  
      if (script.src && /hs-scripts\.com/.test(script.src)) {
           script.onload = () => {
                console.log("HubSpot script loaded, ensuring consent update applied.");
                window._hsq = window._hsq || [];
                _hsq.push(['doNotTrack', !granted]);
           };
           script.onerror = () => console.error(`Failed to load HubSpot script: ${script.src}`);
      }
  }
  
  
  function _handlePlausibleConsentUpdate(script, normalizedPrefs) {
      const granted = normalizedPrefs.analytics === true;
      console.log(`Plausible consent update (handled by script presence/blocking): ${granted}`);
      // Standard integration relies on the script being loaded or not.
      // No JS API call needed typically.
      script.onerror = () => console.error(`Failed to load Plausible script: ${script.src}`);
  }
  
  
  function _handleHotjarConsentUpdate(script, normalizedPrefs) {
      const granted = normalizedPrefs.analytics === true;
      console.log(`Hotjar consent update (handled by script presence/blocking): ${granted}`);
      // Standard integration relies on the script being loaded/initialized or not.
      // Ensure HJ queue exists for potential advanced scenarios, but no standard consent call.
      window.hj = window.hj || function(...args) { (window.hj.q = window.hj.q || []).push(args); };
      window.hj.q = window.hj.q || [];
      script.onerror = () => console.error(`Failed to load Hotjar script: ${script.src}`);
  }
  
  // --- Tool Handler Dispatch Map (Ensure regex escapes dots) ---
  const toolConsentHandlers = [
      { regex: /googletagmanager\.com\/gtag\/js/i, handler: _handleGtagConsentUpdate },
      { regex: /cdn\.(eu\.)?amplitude\.com/i,    handler: _handleAmplitudeConsentUpdate },
      { regex: /clarity\.ms/i,                   handler: _handleClarityConsentUpdate },
      { regex: /connect\.facebook\.net/i,       handler: _handleFacebookPixelConsentUpdate },
      { regex: /matomo\.cloud/i,                 handler: _handleMatomoConsentUpdate },
      { regex: /js\.hs-scripts\.com/i,           handler: _handleHubSpotConsentUpdate }, // More specific HubSpot
      { regex: /plausible\.io/i,                handler: _handlePlausibleConsentUpdate },
      { regex: /static\.hotjar\.com/i,          handler: _handleHotjarConsentUpdate }
  ];
  
  /**
   * Updates consent for specific third-party tools based on granted preferences.
   */
  function _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs) {
      if (!scriptInfo?.src) return;
      const src = scriptInfo.src;
  
      for (const { regex, handler } of toolConsentHandlers) {
          if (regex.test(src)) {
              // console.log(`Found matching tool handler for: ${src}`);
              try {
                  if (handler === _handleClarityConsentUpdate) {
                      handler(normalizedPrefs);
                  } else {
                      handler(script, normalizedPrefs);
                  }
              } catch (toolError) {
                   console.error(`Error running consent handler for ${src}:`, toolError);
              }
              return; // Handler found and called (or errored)
          }
      }
  }
  
  
  // --- REMOVED: _createRestoredScriptElement (integrated into _restoreSingleScript) ---
  
  
  // --- REMOVED: _processSingleScriptRestoration (integrated into restoreAllowedScripts loop) ---
  
  
  // Refactored restoreAllowedScripts
  async function restoreAllowedScripts(preferences) {
      console.log("Restoring allowed scripts based on preferences:", preferences);
      // --- Temporarily disconnect observer ---
      if (observer) {
          observer.disconnect();
          // console.log("MutationObserver temporarily disconnected for restoreAllowedScripts.");
      }
      // ------------------------------------
  
      try {
          // Normalize preferences for consistent checking
          const normalizedPrefs = {
               Necessary: true, // Always true
               Marketing: preferences?.Marketing ?? false,
               Personalization: preferences?.Personalization ?? false,
               Analytics: preferences?.Analytics ?? false,
               ccpa: { // Ensure nested structure
                   donotshare: preferences?.ccpa?.DoNotShare ?? preferences?.DoNotShare ?? false // Normalize key
               }
          };
          // console.log("Normalized preferences for restoration:", normalizedPrefs);
  
          // Process each script placeholder
          const scriptIdsToProcess = Object.keys(existing_Scripts);
          console.log(`Processing ${scriptIdsToProcess.length} stored script placeholders.`);
  
          for (const scriptId of scriptIdsToProcess) {
              const scriptInfo = existing_Scripts[scriptId]; // Get info using ID
              if (!scriptInfo) continue; // Skip if somehow missing
  
              const categories = scriptInfo.category || []; // Already lowercase array
  
              // Check if allowed based on *current* normalized preferences
              if (_isScriptAllowed(categories, normalizedPrefs)) {
                  // Allowed: Check for duplicates before restoring
                  let alreadyExists = false;
                  if (scriptInfo.src) {
                      const existingExecutableScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain']):not([data-consentbit-id])`);
                      if (existingExecutableScript) {
                          alreadyExists = true;
                           // console.log(`Duplicate executable script found for ${scriptInfo.src}. Removing placeholder ${scriptId}.`);
                           const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
                           if (placeholder?.parentNode) placeholder.parentNode.removeChild(placeholder);
                           delete existing_Scripts[scriptId]; // Clean up map
                      }
                  }
  
                  if (!alreadyExists) {
                       // Restore the script (this handles placeholder removal and map cleanup)
                       try {
                           _restoreSingleScript(scriptId, scriptInfo, normalizedPrefs);
                       } catch (singleScriptError) {
                            console.error(`Error processing restoration for scriptId ${scriptId}:`, singleScriptError);
                       }
                  }
              } else {
                   // Not allowed: Ensure placeholder remains or script stays blocked
                   // console.log(`Script ${scriptId} (${scriptInfo.key}) is NOT allowed. Placeholder should remain.`);
                   // Check if placeholder exists, if not, clean map
                   const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
                   if (!placeholder) {
                       // console.warn(`Placeholder for disallowed script ${scriptId} missing.`);
                       delete existing_Scripts[scriptId];
                   }
              }
          } // End loop
  
      } catch (error) {
          console.error("Error during restoreAllowedScripts:", error);
      } finally {
          // --- Reconnect observer ONLY if blocking is still needed ---
          await _updateObserverState(); // Centralized observer logic
          // ------------------------
          console.log("Finished restoring allowed scripts.");
      }
  }
  
  // +++ ADDED: Main Initialization Function +++
  async function initializeConsentManagement() {
      if (isInitialized) {
           console.log("Consent management already initialized.");
           return;
      }
      isInitialized = true;
      console.log("Initializing Consent Management...");
      isLoadingState = true;
  
      try {
          // 1. Try to load existing consent
          const decryptedPreferences = await _getDecryptedPreferences();
          consentState = decryptedPreferences || {}; // Update global state (empty object if null)
  
          if (decryptedPreferences) {
              // 2. Consent Found: Apply saved state & update UI
              console.log("Found existing consent preferences. Applying...");
              currentBannerType = decryptedPreferences.bannerType || null;
              country = decryptedPreferences.consentCountry || null;
  
              await updatePreferenceForm(decryptedPreferences);
              await restoreAllowedScripts(decryptedPreferences);
              console.log("Existing consent applied. Banners should remain hidden.");
  
          } else {
              // 3. No Valid Consent Found: Detect location and proceed
              console.log("No valid consent found. Detecting location...");
              await initializeBannerVisibility(); // Determine bannerType and country
  
              initializeBanner(); // Setup banner event handlers
  
              if (currentBannerType === 'GDPR') {
                  // 4a. GDPR: Block initially, then show banner
                  console.log("GDPR region detected. Blocking scripts initially.");
                  initialBlockingEnabled = true;
                  await scanAndBlockScripts(); // Block existing and setup observer
                  const consentBanner = document.getElementById("consent-banner");
                  if (consentBanner) showBanner(consentBanner); else console.error("GDPR banner element ('consent-banner') not found.");
  
              } else if (currentBannerType === 'CCPA') {
                  // 4b. CCPA: Allow initially, show banner
                  console.log("CCPA region detected. Scripts allowed initially.");
                  initialBlockingEnabled = false;
                  // Ensure observer is NOT active yet
                  await _updateObserverState(); // Should detect blocking not needed initially
                  const ccpaBanner = document.getElementById("initial-consent-banner");
                   if (ccpaBanner) showBanner(ccpaBanner); else console.error("CCPA banner element ('initial-consent-banner') not found.");
  
              } else {
                  // 4c. Unknown/Default: Treat as GDPR (block initially) for safety
                   console.log("Location/Banner type unknown or detection failed. Defaulting to GDPR behavior (blocking scripts initially).");
                   initialBlockingEnabled = true;
                   await scanAndBlockScripts();
                   const consentBanner = document.getElementById("consent-banner");
                   if (consentBanner) showBanner(consentBanner); else console.error("Default GDPR banner element ('consent-banner') not found.");
              }
          }
      } catch (error) {
          console.error("FATAL: Error during consent management initialization:", error);
          // Fallback: Allow all scripts?
          initialBlockingEnabled = false;
          await _updateObserverState(); // Ensure observer is off
          console.warn("Consent initialization failed. Allowing all scripts as a fallback.");
      } finally {
          isLoadingState = false;
          console.log("Consent management initialization complete. Initial Blocking Enabled:", initialBlockingEnabled);
      }
  }
  
  // --- Call the main initialization function ---
  if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initializeConsentManagement);
  } else {
      setTimeout(initializeConsentManagement, 0); // Allow UI rendering cycle first
  }
  
  })(); // End of IIFE
  

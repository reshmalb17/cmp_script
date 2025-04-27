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
  let initialBlockingEnabled = true;

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
    try {
        const [payloadBase64] = token.split('.');
        if (!payloadBase64) {
            // Handle cases where the split doesn't produce the expected parts
            console.error("Invalid token format: Missing payload.");
            return true;
        }
        const payloadString = atob(payloadBase64);
        const payload = JSON.parse(payloadString);

        if (!payload.exp) {
            console.warn("Token payload does not contain 'exp' field.");
            return true; // Treat tokens without expiration as expired/invalid
        }

        const isExpired = payload.exp < Math.floor(Date.now() / 1000);
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
          await response.text();
          return null;
      }

      const data = await response.json();
    
      if (!data.bannerType) {
          return null;
      }
    country =data.country;
      return data;
  } catch (error) {
      // Log the actual error for debugging purposes
      console.error("Error detecting location or banner type:", error);
      // Return null to indicate failure, allowing calling code to handle gracefully
      return null;
  }
}
  
function getClientIdentifier() {
    return window.location.hostname; 
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

/** Helper Functions for attachBannerHandlers **/

// Helper function to attach event listeners safely
function attachListener(id, event, handler) {
  const element = document.getElementById(id);
  if (element) {
      // Use a named function or an async function directly if needed
      element.addEventListener(event, handler);
  } else {
      // Optional: Log if an expected element is missing
      // console.warn(`Element with ID "${id}" not found for attaching listener.`);
  }
}

// --- Individual Event Handler Functions ---

async function handleSimpleAccept(e) {
  e.preventDefault();
  const simpleBanner = document.getElementById("simple-consent-banner"); // Get banner inside handler
  const preferences = { Necessary: true, Marketing: true, Personalization: true, Analytics: true, ccpa: { DoNotShare: false } };
  await saveConsentState(preferences);
  await restoreAllowedScripts(preferences);
  if (simpleBanner) hideBanner(simpleBanner);
  localStorage.setItem("consent-given", "true");
}

async function handleSimpleReject(e) {
  e.preventDefault();
  const simpleBanner = document.getElementById("simple-consent-banner"); // Get banner inside handler
  const preferences = { Necessary: true, Marketing: false, Personalization: false, Analytics: false, ccpa: { DoNotShare: false } };
  await saveConsentState(preferences);
  // Consider if reblockDisallowedScripts or just block based on new scripts is better
  await checkAndBlockNewScripts(); // Ensure new scripts potentially loaded are blocked
  if (simpleBanner) hideBanner(simpleBanner);
  localStorage.setItem("consent-given", "true");
}

function handleToggleConsent(e) {
  e.preventDefault();
  const consentBanner = document.getElementById("consent-banner");
  const ccpaBanner = document.getElementById("initial-consent-banner");

  // Show the appropriate banner based on currentBannerType (ensure it's updated elsewhere)
  if (currentBannerType === 'GDPR') {
      showBanner(consentBanner);
      hideBanner(ccpaBanner);
  } else if (currentBannerType === 'CCPA') {
      showBanner(ccpaBanner);
      hideBanner(consentBanner);
  } else {
      // Default behavior if banner type is unknown or not set
      showBanner(consentBanner); // Or choose a more specific default
      hideBanner(ccpaBanner);
  }
}

function handleDoNotShareLinkClick(e) {
  e.preventDefault();
  const ccpaBanner = document.getElementById("initial-consent-banner");
  const mainConsentBanner = document.getElementById("main-consent-banner");
  hideBanner(ccpaBanner); // Hide initial CCPA banner
  showBanner(mainConsentBanner); // Show CCPA preferences/details banner
}

function handleCloseConsentBanner(e) {
  e.preventDefault();
  const mainConsentBanner = document.getElementById("main-consent-banner");
  hideBanner(mainConsentBanner); // Hide the main CCPA preferences banner
}

async function handleAcceptAll(e) {
  e.preventDefault();
  // acceptAllCookies should handle saving state, restoring scripts, and hiding banners
  await acceptAllCookies();
  // Banners are hidden within acceptAllCookies now
}

async function handleDeclineAll(e) {
  e.preventDefault();
  // blockAllCookies should handle saving state, managing scripts, and hiding banners
  await blockAllCookies();
   // Banners are hidden within blockAllCookies now
}

function handleShowPreferences(e) {
  e.preventDefault();
  const consentBanner = document.getElementById("consent-banner"); // GDPR banner
  const mainBanner = document.getElementById("main-banner");       // GDPR preferences
  hideBanner(consentBanner);
  showBanner(mainBanner);
}

async function handleSaveGdprPreferences(e) {
  e.preventDefault();
  // Query checkboxes inside the handler to ensure they exist at click time
  const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
  const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
  const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
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
  hideBanner(document.getElementById("consent-banner"));
  hideBanner(document.getElementById("main-banner"));
  localStorage.setItem("consent-given", "true");
}

async function handleSaveCcpaPreferences(e) {
  e.preventDefault();
  const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
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

      // Manage scripts based on the DoNotShare state
      await restoreAllowedScripts(preferences); // Restore will handle allowed/disallowed based on prefs

      // Ensure observer is active if scripts are blocked, inactive if all allowed
      if (doNotShare) {
          if (!observer) { // Re-initialize observer if needed
               await scanAndBlockScripts(); // Ensure dynamically added scripts are caught
           }
      } else {
          if (observer) { // Disconnect if we just allowed everything
               observer.disconnect();
               observer = null;
           }
      }

  } catch (error) {
      console.error("Error saving CCPA preferences:", error);
  }

  hideBanner(document.getElementById("initial-consent-banner"));
  hideBanner(document.getElementById("main-consent-banner"));
  localStorage.setItem("consent-given", "true");
}

async function handleCancelPreferences(e) {
  e.preventDefault();
  // Define preferences as declined (only Necessary is true)
  const preferences = {
      Necessary: true, Marketing: false, Personalization: false, Analytics: false,
      // Decide the appropriate CCPA state on cancel, often implies DoNotShare = true
      ccpa: { DoNotShare: true }
  };

  // Save the declined state
  await saveConsentState(preferences);
  // Re-apply blocking based on declined state
  await restoreAllowedScripts(preferences);
   if (!observer) { // Ensure observer is running if needed
       await scanAndBlockScripts();
   }

  // Hide the preference banners
  hideBanner(document.getElementById("main-banner")); // GDPR Prefs
  hideBanner(document.getElementById("main-consent-banner")); // CCPA Prefs

  // Optionally show the initial banner again if needed
  // initializeBannerVisibility();

  localStorage.setItem("consent-given", "true");
}


// --- Refactored attachBannerHandlers Function ---

async function attachBannerHandlers() {
  // Setup necessary checkbox (simple enough to keep inline)
  const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
  if (necessaryCheckbox) {
      necessaryCheckbox.checked = true;
      necessaryCheckbox.disabled = true;
  }

  // Initialize banner visibility first
  // initializeBannerVisibility(); // Called elsewhere now? If not, call here.
  // Assuming initializeBannerVisibility handles showing the *initial* correct banner (GDPR/CCPA/Simple)

  // Attach listeners using the helper
  attachListener("simple-accept", "click", handleSimpleAccept);
  attachListener("simple-reject", "click", handleSimpleReject);
  attachListener("toggle-consent-btn", "click", handleToggleConsent);
  attachListener("new-toggle-consent-btn", "click", handleToggleConsent); // Assumes same logic
  attachListener("do-not-share-link", "click", handleDoNotShareLinkClick);
  attachListener("close-consent-banner", "click", handleCloseConsentBanner);
  attachListener("accept-btn", "click", handleAcceptAll);
  attachListener("decline-btn", "click", handleDeclineAll);
  attachListener("preferences-btn", "click", handleShowPreferences);
  attachListener("save-preferences-btn", "click", handleSaveGdprPreferences); // GDPR Save
  attachListener("save-btn", "click", handleSaveCcpaPreferences); // CCPA Save (Assuming ID is 'save-btn')
  attachListener("cancel-btn", "click", handleCancelPreferences);

  // Remove the explicit simpleBanner show logic here if initializeBannerVisibility handles it
  // const simpleBanner = document.getElementById("simple-consent-banner");
  // if (simpleBanner && !localStorage.getItem("consent-given")) {
  //    showBanner(simpleBanner); // This should likely be part of initializeBannerVisibility
  // }
}
  
  
async function initializeBannerVisibility() {
    //const request = new Request(window.location.href);
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
      // Default to showing GDPR banner (handles GDPR type and unknown/default)
      showBanner(consentBanner);
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

 

async function saveConsentState(preferences) {
  const clientId = getClientIdentifier();
  const visitorId = localStorage.getItem("visitorId");
  const policyVersion = "1.2";
  const timestamp = new Date().toISOString();
  const sessionToken = localStorage.getItem("visitorSessionToken");

  if (!sessionToken) {
    return;
  }

  try {
    const consentPreferences = buildConsentPreferences(preferences, country, timestamp);

    // 1. Generate AES-GCM key and IV
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2. Encode and encrypt preferences
    const encoder = new TextEncoder();

    const encryptedPreferences = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(JSON.stringify(consentPreferences))
    );
    await storeEncryptedConsent(encryptedPreferences, key,iv, timestamp);
    // 3. Encrypt visitor ID (optional but assumed here)
    const encryptedVisitorId = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(visitorId)
    );

    // 4. Export raw key
    const rawKey = await crypto.subtle.exportKey("raw", key);

    // 5. Convert everything to Base64
    const b64Key = arrayBufferToBase64(rawKey);
    const b64IV = arrayBufferToBase64(iv);
    const b64EncryptedPreferences = arrayBufferToBase64(encryptedPreferences);
    const b64EncryptedVisitorId = arrayBufferToBase64(encryptedVisitorId);

    // 6. Build final payload
    const payload = {
      clientId,
      encryptedVisitorId: {
        encryptedPreferences: b64EncryptedVisitorId,
        encryptionKey: {
          key: b64Key,
          iv: b64IV
        }
      },
      preferences: {
        encryptedPreferences: b64EncryptedPreferences,
        encryptionKey: {
          key: b64Key,
          iv: b64IV
        }
      },
      policyVersion,
      timestamp,
      country,
      bannerType: currentBannerType, 
      metadata: {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      }
    };
    // 7. Send payload to server
    const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${sessionToken}`,
      },
      body: JSON.stringify(payload),
    });

    const text = await response.text();
  } catch (error) {
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
      const key = getScriptKey(script);
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
        for (const { pattern, category } of suspiciousPatterns)
             { if (pattern.test(text)) {
                 return category; 
                } } 
                return null; 
            
    }
    

async function loadCategorizedScripts() {
        try {
            // Get session token from localStorage
            const sessionToken = localStorage.getItem('visitorSessionToken');
            if (!sessionToken) {
                console.error('No session token found');
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
                await response.text();
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
                categorizedScripts =responseObj.scripts || [];
                return responseObj.scripts || [];
            } else {
                return [];
            }
        } catch (error) {
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
          let categorySource = matched ? 'server' : 'pattern';
  
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
          let categorySource = matched ? 'server' : 'pattern';
  
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
          // Capture the current state of normalizedCategorized for the observer closure
          const currentNormalizedCategorized = normalizedCategorized;

          observer = new MutationObserver((mutationsList) => {
              for (const mutation of mutationsList) {
                  for (const node of mutation.addedNodes) {
                      // Guard clause: Skip nodes that aren't relevant scripts
                      if (
                          node.tagName !== 'SCRIPT' ||
                          node.hasAttribute('data-consentbit-id') ||
                          node.type === 'text/plain'
                      ) {
                          continue;
                      }

                      // Determine categories using the helper function
                      const { categories } = _getNodeCategories(node, currentNormalizedCategorized);

                      // Block the script using the helper function
                      _blockScriptNode(node, categories);
                  }
              }
          });

          observer.observe(document.documentElement, { childList: true, subtree: true });
      }
  }
  async function acceptAllCookies() {

    // Define preferences for accepting all categories relevant to scripts
    const allAllowedPreferences = {
        Necessary: true,
        Marketing: true,
        Personalization: true,
        Analytics: true,
                 ccpa: { DoNotShare: false } // Example: Assuming accepting all implies sharing is okay
    };

  
    await saveConsentState(allAllowedPreferences); // Pass the full preference object

    await updatePreferenceForm(allAllowedPreferences);

 
    await restoreAllowedScripts(allAllowedPreferences);


    if (observer) {
        observer.disconnect();
        observer = null; // Clear the observer variable
    }

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
      Necessary: true, // Necessary scripts are usually always allowed
      Marketing: false,
      Personalization: false,
      Analytics: false,
    
      ccpa: { DoNotShare: true } // Example: Blocking all might imply DoNotShare = true
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

window.blockAllCookies=blockAllCookies;
window.acceptAllCookies=acceptAllCookies;

  /*CONSENT STATE LOADING AND UI UPDATE */

  /**
   * Attempts to load, parse, and decrypt consent preferences from localStorage.
   * @returns {Promise<object|null>} The decrypted preferences object or null if an error occurs.
   */
  async function _getDecryptedPreferences() {
      try {
          const savedPreferencesRaw = localStorage.getItem("consent-preferences");
          if (!savedPreferencesRaw) {
              return null;
          }

          const savedPreferences = JSON.parse(savedPreferencesRaw);
          if (!savedPreferences?.encryptedData || !savedPreferences.key || !savedPreferences.iv) {
               console.warn("Stored preferences format is invalid.");
               localStorage.removeItem("consent-preferences"); // Clean up invalid data
               return null;
          }

          // Ensure key data is handled correctly (needs to be Uint8Array for importKey)
          const keyBytes = new Uint8Array(savedPreferences.key);
          if (keyBytes.length !== 32) { // AES-256 requires a 32-byte key
              throw new Error("Invalid key length for AES-256 decryption.");
          }
          const key = await crypto.subtle.importKey(
               'raw',
               keyBytes,
               { name: 'AES-GCM', length: 256 },
               false,
               ['decrypt']
           );

          // Assuming savedPreferences.encryptedData is base64 string
          // Need the helper function base64ToArrayBuffer defined
          const encryptedDataBuffer = base64ToArrayBuffer(savedPreferences.encryptedData);

          const decryptedData = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: new Uint8Array(savedPreferences.iv) },
              key,
              encryptedDataBuffer
          );

          const decryptedString = new TextDecoder().decode(decryptedData);
          return JSON.parse(decryptedString);

      } catch (error) {
          console.error("Failed to load or decrypt preferences:", error);
          // Clear potentially corrupted data
          localStorage.removeItem("consent-preferences");
          localStorage.removeItem("consent-given"); // May need to re-ask consent
          return null;
      }
  }

  /**
   * Updates the consent form checkboxes based on the provided state.
   * @param {object} state The consent state object.
   */
  function _updateConsentCheckboxes(state) {
      const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
      const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
      const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
      const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
      const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');

      if (necessaryCheckbox) {
          necessaryCheckbox.checked = true;
          necessaryCheckbox.disabled = true;
      }
      if (marketingCheckbox) {
          marketingCheckbox.checked = state.Marketing || false;
      }
      if (personalizationCheckbox) {
          personalizationCheckbox.checked = state.Personalization || false;
      }
      if (analyticsCheckbox) {
          analyticsCheckbox.checked = state.Analytics || false;
      }
      if (doNotShareCheckbox) {
          doNotShareCheckbox.checked = state.ccpa?.DoNotShare || false;
      }
  }



/**
 * Sets up specific consent-aware tools based on the script's src.
 * This function is called when unblocking all scripts.
 * @param {HTMLScriptElement} script - The newly created script element.
 * @param {object} scriptInfo - The stored information about the original script.
 */
function _setupConsentAwareTool(script, scriptInfo) {
    // Check if scriptInfo or scriptInfo.src is missing
    if (!scriptInfo?.src) {
        return;
    }

    const src = scriptInfo.src;
    const granted = true; // Unblocking all means consent is granted

    // Use a switch statement for clarity or keep if/else if
    if (/googletagmanager\.com\/gtag\/js/.test(src)) {
        setupGoogleAnalytics(script, granted);
    } else if (/clarity\.ms/.test(src)) {
        setupClarity(script, granted);
    } else if (/connect\.facebook\.net/.test(src)) {
        setupFacebookPixel(script, granted);
    } else if (/matomo\.cloud/.test(src)) {
        setupMatomo(script, granted);
    } else if (/hs-scripts\.com/.test(src)) {
        setupHubSpot(script, granted);
    } else if (/plausible\.io/.test(src)) {
        setupPlausible(script, granted);
    } else if (/static\.hotjar\.com/.test(src)) {
        setupHotjar(script, granted);
    } else if (/cdn\.(eu\.)?amplitude\.com/.test(src)) {
        setupAmplitude(script, granted);
    }
    // Add other tools here if needed
}

/**
 * Restores a single blocked script from its placeholder.
 * @param {string} scriptId - The unique ID of the script to restore.
 * @param {object} scriptInfo - The stored information about the original script.
 */
function _restoreSingleScript(scriptId, scriptInfo) {
    if (!scriptInfo) return;

    const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
    if (!placeholder) {
        // Placeholder not found in DOM, clean up reference and exit
        delete existing_Scripts[scriptId];
        return;
    }

    const script = document.createElement("script");

    // Restore core properties
    script.type = scriptInfo.type || "text/javascript";
    if (scriptInfo.async) script.async = true;
    if (scriptInfo.defer) script.defer = true;

    // Restore category attribute (might be useful for debugging)
    const categories = Array.isArray(scriptInfo.category)
        ? scriptInfo.category
        : (scriptInfo.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean);
    script.setAttribute("data-category", categories.join(','));

    // Restore other original attributes *before* setting src or textContent
    if (scriptInfo.originalAttributes) {
        Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
            script.setAttribute(name, value);
        });
    }

    // Restore src or content and setup tools
    if (scriptInfo.src) {
        script.src = scriptInfo.src;
        // Call the tool setup helper
        _setupConsentAwareTool(script, scriptInfo);
    } else {
        script.textContent = scriptInfo.content || ''; // Ensure content is a string
    }

    // Replace placeholder with actual script
    if (placeholder.parentNode) {
         // Ensure the placeholder is still in the DOM before replacing
        if (document.contains(placeholder)) {
            placeholder.parentNode.replaceChild(script, placeholder);
        } else {
             // If placeholder was removed somehow, maybe append to head as fallback?
             console.warn(`Placeholder for scriptId ${scriptId} removed before restoration.`);
             document.head.appendChild(script); // Example fallback
        }

    } else {
        // Fallback if parentNode is somehow null (less likely)
        document.head.appendChild(script);
    }

    // Clean up the entry from our tracking object
    delete existing_Scripts[scriptId];
}

// Refactored unblockAllCookiesAndTools
async function unblockAllCookiesAndTools() {
    // --- Disconnect observer ---
    if (observer) {
        observer.disconnect();
        // Set observer to null as we intend to permanently allow all
        observer = null;
    }
    // ------------------------------------

    try {
        // Set all preferences to true
        const allAllowedPreferences = {
            Necessary: true, Marketing: true, Personalization: true, Analytics: true,
            ccpa: { DoNotShare: false }
        };

        // Save state and update UI
        await saveConsentState(allAllowedPreferences);
        await updatePreferenceForm(allAllowedPreferences); // Assumes updatePreferenceForm exists

        // Restore all scripts by iterating through placeholders
        const scriptIdsToRestore = Object.keys(existing_Scripts);
        for (const scriptId of scriptIdsToRestore) {
            // Call the helper function to restore each script
            _restoreSingleScript(scriptId, existing_Scripts[scriptId]);
        }
        // Note: The loop modifies existing_Scripts via _restoreSingleScript,
        // iterating over Object.keys() handles this safely.

        // Mark consent as given (if not already handled by saveConsentState)
        localStorage.setItem("consent-given", "true");

    } catch (error) {
        // Log errors during the unblocking process
        // No need to reconnect observer here as the intent is permanent allowance.
        console.error("Error during unblockAllCookiesAndTools:", error);
    }
}

/** Helper Functions for restoreAllowedScripts **/

/**
 * Checks if a script category is allowed based on current preferences.
 * @param {Array<string>} categories - Lowercase categories from scriptInfo.
 * @param {object} normalizedPrefs - Lowercase preferences object.
 * @returns {boolean} - True if the script is allowed, false otherwise.
 */
function _isScriptAllowed(categories, normalizedPrefs) {
    // Ensure categories is an array and preferences object exists
    if (!Array.isArray(categories) || !normalizedPrefs) {
        return false;
    }
    // Check if *any* of the script's categories are set to true in preferences
    return categories.some(cat => normalizedPrefs[cat] === true);
}


/** Individual Tool Consent Update Handlers **/

function _handleGtagConsentUpdate(script, normalizedPrefs) {
    const src = script.src; // Get src from script directly
    const consentSettings = {
        'ad_storage': normalizedPrefs.marketing ? 'granted' : 'denied',
        'analytics_storage': normalizedPrefs.analytics ? 'granted' : 'denied',
        'personalization_storage': normalizedPrefs.personalization ? 'granted' : 'denied',
        'functionality_storage': 'granted',
        'security_storage': 'granted',
        'ad_user_data': normalizedPrefs.marketing ? 'granted' : 'denied',
        'ad_personalization': normalizedPrefs.marketing ? 'granted' : 'denied'
    };
    script.onload = () => { if (typeof gtag === "function") gtag('consent', 'update', consentSettings); };
    script.onerror = () => console.error(`Failed to load GA script for consent update: ${src}`);
    if (typeof gtag === "function") gtag('consent', 'update', consentSettings); // Immediate attempt
}

function _handleAmplitudeConsentUpdate(script, normalizedPrefs) {
    const src = script.src;
    const analyticsAllowed = normalizedPrefs.analytics === true;
    const userProperties = {
        consent_analytics: normalizedPrefs.analytics,
        consent_marketing: normalizedPrefs.marketing,
        consent_personalization: normalizedPrefs.personalization || false
    };
    const updateConsent = () => {
        if (typeof amplitude !== "undefined" && amplitude.getInstance) {
            try {
                const instance = amplitude.getInstance();
                instance.setOptOut(!analyticsAllowed);
                instance.setUserProperties(userProperties);
            } catch (error) { console.error("Error setting Amplitude consent:", error); }
        }
    };
    script.onload = () => setTimeout(updateConsent, 100); // Delay on load
    script.onerror = () => console.error(`Failed to load Amplitude script for consent update: ${src}`);
    setTimeout(updateConsent, 0); // Immediate attempt
}

function _handleClarityConsentUpdate(normalizedPrefs) { // Note: Doesn't need script arg
    window.clarity = window.clarity || function(...args) { (window.clarity.q = window.clarity.q || []).push(args); };
    window.clarity.consent = normalizedPrefs.analytics === true;
}

function _handleFacebookPixelConsentUpdate(script, normalizedPrefs) {
    const src = script.src;
    const granted = normalizedPrefs.marketing === true;
    const updateConsent = () => { if (typeof fbq === 'function') fbq('consent', granted ? 'grant' : 'revoke'); };
    script.onload = updateConsent;
    script.onerror = () => console.error(`Failed to load Facebook Pixel script for consent update: ${src}`);
    updateConsent(); // Immediate attempt
}

function _handleMatomoConsentUpdate(script, normalizedPrefs) {
    const src = script.src;
    const granted = normalizedPrefs.analytics === true;
    const updateConsent = () => {
        if (typeof _paq !== 'undefined') {
            if (granted) {
                _paq.push(['setConsentGiven']);
                _paq.push(['trackPageView']);
            } else {
                _paq.push(['forgetConsentGiven']);
            }
        }
    };
    script.onload = updateConsent;
    script.onerror = () => console.error(`Failed to load Matomo script for consent update: ${src}`);
    updateConsent(); // Immediate attempt
}

function _handleHubSpotConsentUpdate(script, normalizedPrefs) {
    const src = script.src;
    const granted = normalizedPrefs.marketing === true || normalizedPrefs.personalization === true;
    const updateConsent = () => { if (typeof _hsq !== 'undefined') _hsq.push(['doNotTrack', { track: granted }]); };
    script.onload = updateConsent;
    script.onerror = () => console.error(`Failed to load HubSpot script for consent update: ${src}`);
    updateConsent(); // Immediate attempt
}

function _handlePlausibleConsentUpdate(script, normalizedPrefs) {
    const granted = normalizedPrefs.analytics === true;
    if (granted) {
        script.setAttribute('data-consent-given', 'true');
    } else {
        script.removeAttribute('data-consent-given');
    }
}

function _handleHotjarConsentUpdate(script, normalizedPrefs) {
    const src = script.src;
    const granted = normalizedPrefs.analytics === true;

    // Initialize HJ queueing mechanism (Refactored)
    // Step 1: Ensure window.hj is the queuing function if it doesn't exist
    window.hj = window.hj || function(...args) { window.hj.q.push(args); };
    // Step 2: Ensure window.hj.q exists as an array on the window.hj object
    window.hj.q = window.hj.q || [];

    const updateConsent = () => { if (typeof hj === 'function') hj('consent', granted ? 'granted' : 'denied'); };
    script.onload = updateConsent;
    script.onerror = () => console.error(`Failed to load Hotjar script for consent update: ${src}`);
    updateConsent(); // Immediate attempt
}

// --- Tool Handler Dispatch Map ---
// Array of objects to maintain order if necessary, though matching logic stops on first hit.
const toolConsentHandlers = [
    { regex: /googletagmanager\.com\/gtag\/js/i, handler: _handleGtagConsentUpdate },
    { regex: /cdn\.(eu\.)?amplitude\.com/i,    handler: _handleAmplitudeConsentUpdate },
    { regex: /clarity\.ms/i,                   handler: _handleClarityConsentUpdate }, // Special case: no script arg
    { regex: /connect\.facebook\.net/i,       handler: _handleFacebookPixelConsentUpdate },
    { regex: /matomo\.cloud/i,                 handler: _handleMatomoConsentUpdate },
    { regex: /hs-scripts\.com/i,              handler: _handleHubSpotConsentUpdate },
    { regex: /plausible\.io/i,                handler: _handlePlausibleConsentUpdate },
    { regex: /static\.hotjar\.com/i,          handler: _handleHotjarConsentUpdate }
    // Add more tools here: { regex: /newtool\.com/i, handler: _handleNewToolConsentUpdate }
];

/**
 * Updates consent for specific third-party tools based on granted preferences. (Refactored)
 * @param {HTMLScriptElement} script - The restored script element.
 * @param {object} scriptInfo - The stored script information (needs src).
 * @param {object} normalizedPrefs - The current consent preferences (lowercase keys).
 */
function _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs) {
    // Guard clause: Need src to identify tools
    if (!scriptInfo?.src) {
        return;
    }
    const src = scriptInfo.src;

    // Iterate through handlers and execute the first match
    for (const { regex, handler } of toolConsentHandlers) {
        if (regex.test(src)) {
            // Call the handler, passing necessary arguments
            // Special handling for handlers that might not need the 'script' element
            if (handler === _handleClarityConsentUpdate) {
                 handler(normalizedPrefs);
            } else {
                 handler(script, normalizedPrefs);
            }
            // Once handled, exit the loop and function
            return;
        }
    }
    // No specific handler found for this script src
}


/**
 * Creates and configures a new script element based on stored info.
 * @param {object} scriptInfo - The stored information about the script.
 * @param {object} normalizedPrefs - Preferences to pass for tool consent updates.
 * @returns {HTMLScriptElement|null} - The configured script element or null if invalid.
 */
function _createRestoredScriptElement(scriptInfo, normalizedPrefs) {
    if (!scriptInfo) return null;

    const script = document.createElement("script");

    // Restore core properties
    script.type = scriptInfo.type || "text/javascript";
    if (scriptInfo.async) script.async = true;
    if (scriptInfo.defer) script.defer = true;

    // Restore category attribute
    const categories = Array.isArray(scriptInfo.category)
        ? scriptInfo.category
        : (scriptInfo.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean);
    script.setAttribute("data-category", categories.join(','));

    // Restore other original attributes
    if (scriptInfo.originalAttributes) {
        Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
            script.setAttribute(name, value);
        });
    }

    // Restore src or content
    if (scriptInfo.src) {
        script.src = scriptInfo.src;
        // Update tool consent *after* setting src and other attrs
        _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs);
    } else {
        script.textContent = scriptInfo.content || '';
    }

    return script;
}

/**
 * Processes the restoration logic for a single blocked script.
 * Finds placeholder, checks allowance & duplicates, creates/replaces script, cleans up.
 * Assumes helpers `_isScriptAllowed` and `_createRestoredScriptElement` exist.
 * Modifies `existing_Scripts` directly by deleting the entry upon successful restoration or cleanup.
 * @param {string} scriptId - The ID of the script placeholder to process.
 * @param {object} normalizedPrefs - The normalized user consent preferences.
 */
function _processSingleScriptRestoration(scriptId, normalizedPrefs) {
    const scriptInfo = existing_Scripts[scriptId];
    if (!scriptInfo) {
        // console.warn(`Script info for ID ${scriptId} not found.`);
        return; // Safety check, script info missing
    }

    const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
    if (!placeholder) {
        // console.warn(`Placeholder for script ID ${scriptId} not found in DOM.`);
        delete existing_Scripts[scriptId]; // Clean up if placeholder is gone
        return;
    }

    // Ensure categories are lowercase and an array
    const categories = Array.isArray(scriptInfo.category)
        ? scriptInfo.category.map(c => c.toLowerCase())
        : (scriptInfo.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean);

    // Check if allowed
    if (!_isScriptAllowed(categories, normalizedPrefs)) {
        // Not allowed, leave placeholder as is.
        return;
    }

    // --- Script is allowed, proceed with restoration ---

    // Check for duplicates (only for scripts with src for simplicity)
    let alreadyExists = false;
    if (scriptInfo.src) {
        const existingScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain']):not([data-consentbit-id])`);
        if (existingScript) {
            alreadyExists = true;
        }
    } // Inline script duplicate check skipped

    if (alreadyExists) {
        // Remove placeholder, clean up, and exit
        if (placeholder.parentNode && document.contains(placeholder)) {
            placeholder.parentNode.removeChild(placeholder);
        }
        delete existing_Scripts[scriptId];
        // console.log(`Removed duplicate placeholder for: ${scriptInfo.src || 'inline script ' + scriptId}`);
        return;
    }

    // Create the script element using the helper
    const script = _createRestoredScriptElement(scriptInfo, normalizedPrefs);
    if (!script) {
        console.error(`Failed to create script element for scriptId ${scriptId}`);
        return; // Stop if script creation failed
    }

    // Replace placeholder or fallback
    let replacedOrAppended = false;
    if (placeholder.parentNode && document.contains(placeholder)) {
        try {
            placeholder.parentNode.replaceChild(script, placeholder);
            replacedOrAppended = true;
        } catch (replaceError) {
             console.error(`Error replacing placeholder for scriptId ${scriptId}:`, replaceError);
             // Attempt fallback if replacement failed
             try {
                  document.head.appendChild(script);
                  replacedOrAppended = true; // Consider it handled if append works
             } catch (appendError) {
                  console.error(`Error appending script ${scriptId} to head as fallback:`, appendError);
             }
        }
    } else {
        // Fallback if placeholder or its parent is gone
        console.warn(`Placeholder or parentNode missing for scriptId ${scriptId}. Appending to head.`);
        try {
            document.head.appendChild(script);
            replacedOrAppended = true;
        } catch (appendError) {
            console.error(`Error appending script ${scriptId} to head as fallback:`, appendError);
        }
    }

    // Clean up if replacement or append was successful
    if (replacedOrAppended) {
        delete existing_Scripts[scriptId];
    } else {
        // If script creation succeeded but adding to DOM failed, it's an issue.
        console.error(`Failed to add script ${scriptId} to the DOM.`);
    }
}

// Refactored restoreAllowedScripts
async function restoreAllowedScripts(preferences) {
    // --- Temporarily disconnect observer ---
    if (observer) {
        observer.disconnect();
    }
    // ------------------------------------

    try {
        // Normalize preferences keys to lowercase for consistent checking
        const normalizedPrefs = Object.fromEntries(
            Object.entries(preferences || {}).map(([key, value]) => {
                // Handle nested ccpa object
                if (key.toLowerCase() === 'ccpa' && typeof value === 'object' && value !== null) {
                    return [key.toLowerCase(), {
                        donotshare: value.DoNotShare || value.donotshare || false // Normalize DoNotShare key
                    }];
                }
                return [key.toLowerCase(), value];
            })
        );

        // Process each script using the helper
        // Iterate over a copy of keys as the helper modifies the object
        const scriptIdsToProcess = Object.keys(existing_Scripts);
        for (const scriptId of scriptIdsToProcess) {
            // Use try-catch around individual processing if one script failure
            // shouldn't stop others (optional, adds slight complexity back)
            try {
                _processSingleScriptRestoration(scriptId, normalizedPrefs);
            } catch (singleScriptError) {
                 console.error(`Error processing restoration for scriptId ${scriptId}:`, singleScriptError);
                 // Continue to next script despite error with this one
            }
        }

    } catch (error) {
        // Catch errors during preference normalization or loop setup
        console.error("Error during restoreAllowedScripts setup:", error);
    } finally {
        // --- Reconnect observer ---
        if (observer) {
            // Use a short delay to avoid observing the changes made by this function itself
            setTimeout(() => {
                 if (observer) { // Check again in case it was set to null elsewhere concurrently
                    observer.observe(document.documentElement, { childList: true, subtree: true });
                 }
            }, 50);
        }
        // ------------------------
    }
}

})();

(async function () {
  const existing_Scripts = {}; // Change to object/map instead of array
  let scriptIdCounter = 0; // Add this line
  let isLoadingState = false;
  let consentState = {};
  let observer;
  let isInitialized = false;
  let currentBannerType = null;
  let country = null;
  let categorizedScripts = null;
  let initialBlockingEnabled = true;

    const suspiciousPatterns = [ { pattern: /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview/i, category: "Analytics" }, { pattern: /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|matomo/i, category: "Marketing" }, { pattern: /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i, category: "Personalization" } ];


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


     /**
  ENCRYPTION AND DECYPTION ENDS

 /*LOCATION DETECTION AND BANNER TYPE STARTS*/

 /*LOCATION DETECTION AND BANNER TYPE ENDS*/
 // Function to check if token is expired
 function isTokenExpired(token) {
    try {
        const [payloadBase64] = token.split('.');
        const payload = JSON.parse(atob(payloadBase64));
        
        if (!payload.exp) return true;
        
        return payload.exp < Math.floor(Date.now() / 1000);
    } catch (error) {
        console.error('Error checking token expiration:', error);
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
          console.log("No visitor session token found in detect location");
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
          // credentials: 'include'
      });

      if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('Failed to load banner type:', errorData);
          return null;
      }

      const data = await response.json();
      // Changed to check for bannerType instead of scripts
      if (!data.bannerType) {
          console.error('Invalid banner type data format');
          return null;
      }
    country =data.country;
      return data;
  } catch (error) {
      console.error('Error detecting location:', error);
      return null;
  }
}
  
function getClientIdentifier() {
    return window.location.hostname; // Use hostname as the unique client identifier
    }

    async function reblockDisallowedScripts(consentState) {
      console.log("Reblocking scripts based on updated consent preferences");
  
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
  
                  console.log("Blocked external script again:", originalSrc);
              }
  
              // Inline script
              else if (!script.src && script.textContent && !script.hasAttribute("data-blocked-inline")) {
                  const placeholder = createPlaceholder(script, categoriesAttr);
                  if (placeholder) {
                      script.parentNode.replaceChild(placeholder, script);
                      existing_Scripts.push(placeholder);
                      console.log("Re-blocked inline script for categories:", categoriesAttr);
                  }
              }
          }
      });
  }
  
    
/*BANNER */

async function attachBannerHandlers() {
    const consentBanner = document.getElementById("consent-banner");
    const ccpaBanner = document.getElementById("initial-consent-banner");
    const mainBanner = document.getElementById("main-banner");
    const mainConsentBanner = document.getElementById("main-consent-banner");
    const simpleBanner = document.getElementById("simple-consent-banner");
    const simpleAcceptButton = document.getElementById("simple-accept");
    const simpleRejectButton = document.getElementById("simple-reject");
  
    // Button elements
    const toggleConsentButton = document.getElementById("toggle-consent-btn");
    const newToggleConsentButton = document.getElementById("new-toggle-consent-btn");
    const acceptButton = document.getElementById("accept-btn");
    const declineButton = document.getElementById("decline-btn");
    const preferencesButton = document.getElementById("preferences-btn");
    const savePreferencesButton = document.getElementById("save-preferences-btn");
    const saveCCPAPreferencesButton = document.getElementById("save-btn");
    const cancelButton = document.getElementById("cancel-btn");
    const closeConsentButton = document.getElementById("close-consent-banner");
    const doNotShareLink = document.getElementById("do-not-share-link");
    doNotShareLink? "true":"false";
  
    // Checkbox elements
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]')
    const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]')
    const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]')
    const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]')
    const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
    if (necessaryCheckbox) {
      necessaryCheckbox.checked = true;              // Always checked
      necessaryCheckbox.disabled = true;             // Prevent user from unchecking
    }
    // Initialize banner visibility based on user location
    initializeBannerVisibility();
  
    if (simpleBanner) {
      console.log('Simple banner found, initializing handlers'); // Debug log
      showBanner(simpleBanner);
  
      if (simpleAcceptButton) {
        simpleAcceptButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Accept button clicked');
          const preferences = {
            Necessary: true,
            Marketing: true,
            Personalization: true,
            Analytics: true,
            DoNotShare: false
          };
          
            await saveConsentState(preferences);
             restoreAllowedScripts(preferences);
             hideBanner(simpleBanner);
            localStorage.setItem("consent-given", "true");
          
          });
        }
      
  
      if (simpleRejectButton) {
        simpleRejectButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Reject button clicked');
          const preferences = {
            Necessary: true,
            Marketing: false,
            Personalization: false,
            Analytics: false,
            DoNotShare: true
          };
          await saveConsentState(preferences);
          checkAndBlockNewScripts();
          hideBanner(simpleBanner);
          localStorage.setItem("consent-given", "true");
        });
      }
    }
    
  
    if (toggleConsentButton) {
      toggleConsentButton.addEventListener("click", async function(e) {
          e.preventDefault();
  
          
          const consentBanner = document.getElementById("consent-banner");
          const ccpaBanner = document.getElementById("initial-consent-banner");
          const simpleBanner = document.getElementById("simple-consent-banner");
          //console.log('Location Data:', window.currentLocation); // Log the location data for debugging
          //console.log('Banner Type:', window.currentBannerType);
  
          // Show the appropriate banner based on bannerType
          if (currentBannerType === 'GDPR') {
              showBanner(consentBanner); // Show GDPR banner
              hideBanner(ccpaBanner); // Hide CCPA banner
          } else if (currentBannerType === 'CCPA') {
              showBanner(ccpaBanner); // Show CCPA banner
              hideBanner(consentBanner); // Hide GDPR banner
          } else {
              showBanner(consentBanner); // Default to showing GDPR banner
              hideBanner(ccpaBanner);
          }
      });
  }
  
  if (newToggleConsentButton) {
    newToggleConsentButton.addEventListener("click", async function(e) {
      e.preventDefault();
      //console.log('New Toggle Button Clicked'); // Log for debugging
  
      const consentBanner = document.getElementById("consent-banner");
      const ccpaBanner = document.getElementById("initial-consent-banner");
  
      // Show the appropriate banner based on bannerType
      if (currentBannerType === 'GDPR') {
        showBanner(consentBanner); // Show GDPR banner
        hideBanner(ccpaBanner); // Hide CCPA banner
      } else if (currentBannerType === 'CCPA') {
        showBanner(ccpaBanner); // Show CCPA banner
        hideBanner(consentBanner); // Hide GDPR banner
      } else {
        showBanner(consentBanner); // Default to showing GDPR banner
        hideBanner(ccpaBanner);
      }
    });
  }
  
    if (doNotShareLink) {
      
      doNotShareLink.addEventListener("click", function(e) {
        
        e.preventDefault();
        hideBanner(ccpaBanner); // Hide CCPA banner if it's open
        showBanner(mainConsentBanner); // Show main consent banner
      });
    }
  
  
    if (closeConsentButton) {
      closeConsentButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(document.getElementById("main-consent-banner")); // Hide the main consent banner
      });
    }
    // Accept button handler
    if (acceptButton) {
      acceptButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          Necessary: true,
          Marketing: true,
          Personalization: true,
          Analytics: true
        };
        await saveConsentState(preferences);
       await acceptAllCookies();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    // Decline button handler
    if (declineButton) {
      declineButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          Necessary: true,
          Marketing: false,
          Personalization: false,
          Analytics: false
        };
        await saveConsentState(preferences);
        await blockAllCookies();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    // Preferences button handler
    if (preferencesButton) {
      preferencesButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(consentBanner);
        showBanner(mainBanner);
      });
    }
  
    if (savePreferencesButton) {
       console.log(" inside save preference click")
      savePreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          Necessary: true, // Always true
          Marketing: marketingCheckbox?.checked || false,
          Personalization: personalizationCheckbox?.checked || false,
          Analytics: analyticsCheckbox?.checked || false,
           ccpa: {
              DoNotShare : false
           }
          
        };
        console.log("Preference selected",preferences);
        try{
            await saveConsentState(preferences);
            console.log("calling unblock script");
            await restoreAllowedScripts(preferences);
        }catch(error){
            console.log(error)
        }
        
      
        hideBanner(consentBanner);
            hideBanner(mainBanner);
      });
    }
  
    if (saveCCPAPreferencesButton) {
      saveCCPAPreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const doNotShare = doNotShareCheckbox.checked;
        const preferences = {
          Necessary: true, // Always true
           DoNotShare: doNotShare // Set doNotShare based on checkbox
        };
     
        
        // Block or unblock scripts based on the checkbox state
        if (doNotShare) {
          await blockAllCookies();
         
          await saveConsentState(preferences);
        } else {
          restoreAllowedScripts(preferences); // Unblock scripts if checkbox is unchecked
        }
       
      
        hideBanner(ccpaBanner);
        hideBanner(mainConsentBanner);
        console.assertLOG
      });
    }
  
    // Cancel button handler
    if (cancelButton) {
      cancelButton.addEventListener("click", function(e) {
        e.preventDefault();


  
    
          // Get references to checkboxes again inside this handler for safety
          const consentBanner = document.getElementById("consent-banner"); // Ensure consentBanner is accessible
          const mainBanner = document.getElementById("main-banner");       // Ensure mainBanner is accessible
          const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
          const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
          const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
    
          // Uncheck optional checkboxes
          if (marketingCheckbox) marketingCheckbox.checked = false;
          if (personalizationCheckbox) personalizationCheckbox.checked = false;
          if (analyticsCheckbox) analyticsCheckbox.checked = false;
    
          // Define preferences as declined (only Necessary is true)
          const preferences = {
            Necessary: true,
            Marketing: false,
            Personalization: false,
            Analytics: false
            // Note: DoNotShare status isn't typically managed here, it has its own flow
          };
    
          // Save the declined state
           saveConsentState(preferences); 
           reblockDisallowedScripts(preferences);
          localStorage.setItem("consent-given", "true"); // Mark consent as handled
  
             
          
          hideBanner(consentBanner); 
          hideBanner(mainBanner);    
        });








        hideBanner(consentBanner);
        hideBanner(mainBanner);
      }
      
    
    }
    
  
async function initializeBannerVisibility() {
    //const request = new Request(window.location.href);
    const locationData = await detectLocationAndGetBannerType();  
    console.log("Location Data",locationData);
    currentBannerType = locationData?.bannerType;
    country = locationData?.country;  
    const consentGiven = localStorage.getItem("consent-given");
    const consentBanner = document.getElementById("consent-banner"); // GDPR banner
    const ccpaBanner = document.getElementById("initial-consent-banner"); // CCPA banner
    const mainBanner = document.getElementById("main-banner"); // Main banner
    const mainConsentBanner = document.getElementById("main-consent-banner"); 

    if (consentGiven === "true") {
      //console.log("Consent already given, skipping banner display.");
      hideBanner(consentBanner);
      hideBanner(ccpaBanner);
      return; 
    }
    // Show the appropriate banner based on location
    if (currentBannerType === "GDPR") {
      showBanner(consentBanner); // Show GDPR banner
      hideBanner(ccpaBanner); // Hide CCPA banner
    } else if (currentBannerType === "CCPA") {
      showBanner(ccpaBanner); // Show CCPA banner
      hideBanner(consentBanner); // Hide GDPR banner
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



async function saveConsentState(preferences) {
  const clientId = getClientIdentifier();
  const visitorId = localStorage.getItem("visitorId");
  const policyVersion = "1.2";
  const timestamp = new Date().toISOString();
  const sessionToken = localStorage.getItem("visitorSessionToken");

  if (!sessionToken) {
    console.error("Failed to retrieve authentication token.");
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
    console.log("called function buildPayload ");
    console.log("called https://cb-server.web-8fb.workers.dev/api/cmp/consent ");
    console.log("payload", payload);

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
    console.log("Consent section response:", text);
    console.log("SAVE CONSENT STATE FINISHES..");
  } catch (error) {
    console.error("Error in saveConsentState:", error);
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
      console.error("Error storing encrypted consent:", error);
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
      console.log("✅ All scripts are already blocked.");
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
                const errorData = await response.json().catch(() => ({}));
                console.error('Failed to load categorized scripts:', errorData);
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
                console.log("decrypted Script category",responseObj.scripts)
                categorizedScripts =responseObj.scripts || [];
                console.log("initial categorized script",categorizedScripts);
                return responseObj.scripts || [];
            } else {
                console.error('Response does not contain encrypted data');
                return [];
            }
        } catch (error) {
            console.error('Error loading categorized scripts:', error);
            return [];
        }
      } 
 function extractCategories(content) {
        if (!content) return [];
        
        // Extract data-category attribute value
        const categoryMatch = content.match(/data-category=["']([^"']+)["']/);
        if (categoryMatch && categoryMatch[1]) {
            // Split by comma and clean up each category
            return categoryMatch[1]
                .split(',')
                .map(cat => cat.trim())
                .filter(Boolean); // Remove empty strings
        }
    
        // If no data-category found in content
        return [];
    }
    
    async function scanAndBlockScripts() {
      console.log("inside scan and block");
  
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
                  console.log(`Blocked external script ${script.src} with categories [${scriptCategories.join(',')}] (source: ${categorySource})`);
              } else {
                  console.error("Could not create/replace placeholder for:", script.src);
              }
          } else {
             // console.log("Script not categorized, allowing:", script.src);
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
                  console.log(`Blocked inline script with categories [${scriptCategories.join(',')}] (source: ${categorySource})`);
              } else {
                   console.error("Could not create/replace placeholder for inline script.");
              }
          } else {
             // console.log("Inline script not categorized, allowing.");
          }
      });
  
      // Setup MutationObserver after initial scan (if not already observing)
      if (!observer) {
          observer = new MutationObserver((mutationsList) => {
              for (const mutation of mutationsList) {
                  for (const node of mutation.addedNodes) {
                      // Check if it's a script, not already a placeholder, and not type/plain
                      if (
                          node.tagName === 'SCRIPT' &&
                          !node.hasAttribute('data-consentbit-id') &&
                          node.type !== 'text/plain'
                      ) {
                          let categories = [];
                          let categorySource = 'unknown';
  
                          if (node.src) {
                              const normalizedSrc = normalizeUrl(node.src);
                              const matched = normalizedCategorized.find(s => s.normalizedSrc === normalizedSrc);
                              if (matched) {
                                  categories = matched.categories;
                                  categorySource = 'server';
                              } else {
                                  const patternCategory = findCategoryByPattern(node.src);
                                  if (patternCategory) {
                                      categories = [patternCategory];
                                      categorySource = 'pattern';
                                  }
                              }
                          } else {
                               const content = node.textContent.trim().replace(/\s+/g, '');
                               if(content){ // Only process if there's content
                                  const matched = normalizedCategorized.find(s => s.normalizedContent === content);
                                  if (matched) {
                                      categories = matched.categories;
                                      categorySource = 'server';
                                  } else {
                                      const patternCategory = findCategoryByPattern(node.textContent);
                                      if (patternCategory) {
                                          categories = [patternCategory];
                                          categorySource = 'pattern';
                                      }
                                  }
                               }
                          }
  
                          // If the dynamically added script is categorized, block it
                          if (categories.length > 0) {
                               console.log(`Blocking dynamically injected script (${node.src || 'inline'}) with categories [${categories.join(',')}] (source: ${categorySource})`);
                              const placeholder = createPlaceholder(node, categories.join(','));
                              if (placeholder && node.parentNode) {
                                  node.parentNode.replaceChild(placeholder, node);
                              }
                           } else {
                             console.log(`Allowing dynamically injected script (${node.src || 'inline'}) - not categorized.`);
                           }
                      }
                  }
              }
          });
  
          observer.observe(document.documentElement, { childList: true, subtree: true });
          console.log("MutationObserver is now active.");
      }
  }
  async function acceptAllCookies() {
    console.log("ACCEPT ALL COOKIES triggered");

    // Define preferences for accepting all categories relevant to scripts
    const allAllowedPreferences = {
        Necessary: true,
        Marketing: true,
        Personalization: true,
        Analytics: true,
        // Include other categories if scripts use them
        // Reset DoNotShare if applicable to your logic (e.g., for CCPA)
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
        console.log("Disconnecting MutationObserver as all scripts are allowed.");
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

    console.log("ACCEPT ALL COOKIES finished");
}
// Make sure it's globally accessible if called from HTML etc.
window.acceptAllCookies = acceptAllCookies;
async function blockAllCookies() {
  console.log("BLOCK ALL COOKIES triggered (Rejecting non-necessary)");

  // Define preferences for blocking all non-necessary categories
  const rejectNonNecessaryPreferences = {
      Necessary: true, // Necessary scripts are usually always allowed
      Marketing: false,
      Personalization: false,
      Analytics: false,
      // Handle CCPA 'DoNotShare' based on your logic for "block all"
      ccpa: { DoNotShare: true } // Example: Blocking all might imply DoNotShare = true
  };

  // 1. Save the "reject non-necessary" consent state
  await saveConsentState(rejectNonNecessaryPreferences);

  // 2. Update the preference form display (if visible)
  await updatePreferenceForm(rejectNonNecessaryPreferences);

  // 3. Ensure scripts are blocked according to these preferences.
  // Calling restoreAllowedScripts with 'false' for categories ensures
  // only 'Necessary' scripts run, and others remain placeholders.
  // It effectively "re-blocks" anything that shouldn't be running.
  console.log("Applying 'block all' preferences to scripts...");
  await restoreAllowedScripts(rejectNonNecessaryPreferences);

  // 4. Ensure the MutationObserver is running to catch dynamic scripts.
  // scanAndBlockScripts sets up the observer if it's not already running.
  // If it was disconnected by acceptAllCookies, we might need to re-initialize it.
  if (!observer) {
      console.log("MutationObserver was not active. Re-running scanAndBlockScripts to ensure observer is set up.");
      // Re-running scan might be redundant if placeholders are already correct,
      // but it ensures the observer is active. Consider a lighter way to just restart the observer if needed.
      await scanAndBlockScripts();
  } else {
      console.log("MutationObserver is active.");
  }


  // 5. Hide banners
  hideBanner(document.getElementById("consent-banner"));
  hideBanner(document.getElementById("initial-consent-banner")); // CCPA
  hideBanner(document.getElementById("main-banner")); // GDPR Preferences
  hideBanner(document.getElementById("main-consent-banner")); // CCPA Preferences
  hideBanner(document.getElementById("simple-consent-banner"));

  localStorage.setItem("consent-given", "true"); // Mark consent as handled

  console.log("BLOCK ALL COOKIES finished");
}
// Make sure it's globally accessible if called from HTML etc.
window.blockAllCookies = blockAllCookies;

window.blockAllCookies=blockAllCookies;
window.acceptAllCookies=acceptAllCookies;

  async function loadConsentState() {
    console.log("LOAD CONSENT STATE STARTS");

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
                    console.log("Decrypted preferences:", preferences);

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
                console.error("Error decrypting preferences:", error);
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
        console.error("Error in loadConsentState:", error);
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

    console.log("LOAD CONSENT STATE ENDS");
    return consentState;
}  


async function restoreAllowedScripts(preferences) {
  console.log("RESTORE STARTS");

  // Normalize preferences keys to lowercase for consistent checking
  const normalizedPrefs = Object.fromEntries(
      Object.entries(preferences).map(([key, value]) => [key.toLowerCase(), value])
  );

  console.log("Scripts to potentially restore:", Object.keys(existing_Scripts).length);
  console.log("Current preferences:", normalizedPrefs);

  // Iterate over a copy of the keys, as we might modify the object during iteration
  const scriptIdsToRestore = Object.keys(existing_Scripts);

  for (const scriptId of scriptIdsToRestore) {
      const scriptInfo = existing_Scripts[scriptId];
      if (!scriptInfo) continue; // Should not happen, but safety check

      // Find the placeholder in the DOM
      const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
      if (!placeholder) {
          console.warn(`Placeholder for script ID ${scriptId} not found in DOM. Skipping restore.`);
          // Clean up the entry if the placeholder is gone
          delete existing_Scripts[scriptId];
          continue;
      }

      // Determine if the script is allowed based on its categories and current preferences
      const isAllowed = scriptInfo.category.some(cat => normalizedPrefs[cat] === true);

      console.log(`Script ID: ${scriptId}, Categories: [${scriptInfo.category.join(',')}], Allowed: ${isAllowed}`);

      if (isAllowed) {
          // Check if a script with this src already exists in the DOM (prevent duplicates)
          if (scriptInfo.src) {
               // More specific check: Look for scripts with the same src that are NOT placeholders
              const existingScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain'])`);
              if (existingScript && existingScript !== placeholder) {
                  console.log(`Script with src ${scriptInfo.src} already exists. Skipping restore for ID ${scriptId}.`);
                   // Remove the placeholder if the script already exists elsewhere
                  if (placeholder.parentNode) {
                       placeholder.parentNode.removeChild(placeholder);
                   }
                  delete existing_Scripts[scriptId]; // Clean up the reference
                  continue; // Move to the next script
              }
          }


          console.log(`Restoring script ID: ${scriptId} (${scriptInfo.src || 'inline'})`);
          const script = document.createElement("script");

          // Restore core properties
          script.type = scriptInfo.type; // Restore original type
          if (scriptInfo.async) script.async = true;
          if (scriptInfo.defer) script.defer = true;
          script.setAttribute("data-category", scriptInfo.category.join(',')); // Keep category info if needed

          // Restore src or content
          if (scriptInfo.src) {
              script.src = scriptInfo.src;

              // Special handling for GA or other consent-aware scripts
              const gtagPattern = /googletagmanager\.com\/gtag\/js/i;
              if (gtagPattern.test(scriptInfo.src)) {
                  console.log("Detected GA script, hooking into consent update");
                  function updateGAConsent() {
                      if (typeof gtag === "function") {
                          console.log("Updating GA consent settings...");
                          gtag('consent', 'update', {
                              'ad_storage': normalizedPrefs.marketing ? 'granted' : 'denied',
                              'analytics_storage': normalizedPrefs.analytics ? 'granted' : 'denied',
                              'ad_personalization': normalizedPrefs.marketing ? 'granted' : 'denied', // Adjust based on your categories
                              'ad_user_data': normalizedPrefs.marketing ? 'granted' : 'denied'      // Adjust based on your categories
                          });
                      } else {
                          console.warn("gtag is not defined yet. Will retry on script load.");
                      }
                  }
                  // Update on load
                   script.onload = () => {
                       console.log(`GA script (${scriptInfo.src}) loaded.`);
                       updateGAConsent();
                       // Restore other original attributes after load if necessary
                      // Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                      //     script.setAttribute(name, value);
                      // });
                   };
                   script.onerror = () => {
                       console.error(`Failed to load GA script: ${scriptInfo.src}`);
                   }
                  // Attempt immediate update if gtag exists
                  updateGAConsent();
              } else {
                   // Restore other attributes for non-GA scripts immediately or on load
                  Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                       script.setAttribute(name, value);
                   });
              }

          } else {
              script.textContent = scriptInfo.content;
               // Restore other attributes for inline scripts
               Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                   script.setAttribute(name, value);
               });
          }

          // Replace the placeholder with the restored script
          if (placeholder.parentNode) {
              placeholder.parentNode.replaceChild(script, placeholder);
          } else {
               console.warn(`Placeholder parent node not found for script ID ${scriptId}. Appending to head.`);
               document.head.appendChild(script); // Fallback: append to head
          }

          // Remove the script info from our tracking object *after* successful restoration
          delete existing_Scripts[scriptId];

      } else {
          console.log(`Script ID: ${scriptId} remains blocked.`);
          // Ensure the node in the DOM is still a placeholder (it should be)
           if (placeholder.tagName !== 'SCRIPT' || placeholder.type !== 'text/plain') {
               console.warn(`Node for script ID ${scriptId} is not a placeholder as expected.`);
               // Optionally, try to re-block it here if necessary, though ideally,
               // reblockDisallowedScripts would handle this later if consent changes.
           }
      }
  }

  console.log("Scripts remaining in existing_Scripts map:", Object.keys(existing_Scripts).length);
  console.log("RESTORE ENDS");
}
          

  /* INITIALIZATION */
  async function getVisitorSessionToken() {
    try {
        // Check if we have a valid token in localStorage first
        const existingToken = localStorage.getItem('visitorSessionToken');
        if (existingToken && !isTokenExpired(existingToken)) {
            console.log("Using existing token from localStorage");
            return existingToken;
        }

        // Get or create visitor ID
        const visitorId = await getOrCreateVisitorId();
        
        // Get cleaned site name
        const siteName = await cleanHostname(window.location.hostname);
        
        console.log("Requesting new visitor session token...");
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
        console.log("Successfully obtained new visitor session token");
        
        return data.token;
    } catch (error) {
        console.error('Error getting visitor session token:', error);
        return null;
    }
}
 

   function blockAllInitialRequests() {
    const originalFetch = window.fetch;
    window.fetch = function (...args) {
        const url = args[0];
        if (initialBlockingEnabled && isSuspiciousResource(url)) {
            
            return Promise.resolve(new Response(null, { status: 204 }));
        }
        return originalFetch.apply(this, args);
    };
    
    const originalXHR = window.XMLHttpRequest;
      window.XMLHttpRequest = function() {
        const xhr = new originalXHR();
        const originalOpen = xhr.open;
        
        xhr.open = function(method, url) {
          if (initialBlockingEnabled && isSuspiciousResource(url)) {
            
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
            if (name === 'src' && initialBlockingEnabled && isSuspiciousResource(value)) {
                
                return;
            }
            return originalSetAttribute.apply(this, arguments);
        };
        return img;
    };
    }   
  
  
  
 async  function initializeAll() {
    if (isInitialized) {
      
      return;
    }
    
    
    // Block everything first
    blockAllInitialRequests();
    
    // Then load state and initialize banner
    loadConsentState().then(() => {
      initializeBanner();
      
      isInitialized = true;
    });
   }
      
  async  function loadConsentStyles() {
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
        link.onerror = function() {
            console.error('Failed to load consent styles');
        };
        
        // Add load confirmation
        link.onload = function() {
            console.log('Consent styles loaded successfully');
        };
        
        document.head.appendChild(link);
    } catch (error) {
        console.error('Error loading consent styles:', error);
    }
}
window.loadConsentStyles =loadConsentStyles;
window.loadConsentState = loadConsentState;
window.scanAndBlockScripts = scanAndBlockScripts;
window.initializeBanner= initializeBanner;
window.attachBannerHandlers = attachBannerHandlers;
window.showBanner = showBanner;
window.hideBanner = hideBanner;
window.checkAndBlockNewScripts = checkAndBlockNewScripts;
window.createPlaceholder = createPlaceholder;
window.restoreAllowedScripts = restoreAllowedScripts;
window.loadCategorizedScripts =loadCategorizedScripts;
window.detectLocationAndGetBannerType = detectLocationAndGetBannerType;
window.getVisitorSessionToken = getVisitorSessionToken;
window.isTokenExpired = isTokenExpired;
  window.cleanHostname = cleanHostname;
  window.getOrCreateVisitorId = getOrCreateVisitorId;
  window.buildConsentPreferences= buildConsentPreferences;
  window.storeEncryptedConsent=storeEncryptedConsent;
  window.buildPayload = buildPayload;
  window.getClientIdentifier =getClientIdentifier;
  window.getScriptKey = getScriptKey;
  window.getCategoryFromScript =getCategoryFromScript;
  window.getCategoryFromContent =getCategoryFromContent;
  window.isScriptAlreadyBlocked = isScriptAlreadyBlocked;
  window.findCategoryByPattern =findCategoryByPattern;
  window.normalizeUrl = normalizeUrl;
  window.initializeAll = initializeAll;
  window.blockAllInitialRequests =blockAllInitialRequests;
  window.reblockDisallowedScripts=reblockDisallowedScripts;

document.addEventListener('DOMContentLoaded',  initialize);

async function loadAndApplySavedPreferences() {
  console.log("Loading and applying saved preferences...");
  
  if (isLoadingState) {
  console.log("isloading state...",isLoadingState);

      return;
  }
  isLoadingState = true;

  try {
      const consentGiven = localStorage.getItem("consent-given");
      console.log("consent given",consentGiven);
      

      
      if (consentGiven === "true") {
          const savedPreferences = localStorage.getItem("consent-preferences");
          console.log("saved preferences",savedPreferences);
          
          if (savedPreferences) {
              try {
                  const parsedPrefs = JSON.parse(savedPreferences);
                  console.log("Parsed preferences",parsedPrefs)
                  
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
                  
                  // Decrypt using the same format as encryption
                  const decryptedData = await crypto.subtle.decrypt(
                      { name: 'AES-GCM', iv: new Uint8Array(parsedPrefs.iv) },
                      key,
                      encryptedData
                  );
                  console.log("decrypted saved preference",decryptedData);
                  

                  const preferences = JSON.parse(new TextDecoder().decode(decryptedData));
                  console.log("Decrypted preferences:", preferences);

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
                  console.error("Error decrypting preferences:", error);
                  localStorage.removeItem("consent-preferences");
              }
          }
      }
  } catch (error) {
      console.error("Error loading preferences:", error);
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
  console.log("___INSIDE UPDATE PREFERENCE___");


  // Get checkbox elements
  const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
  const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
  const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
  const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
  const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');

  if (!necessaryCheckbox && !marketingCheckbox && !personalizationCheckbox && 
      !analyticsCheckbox && !doNotShareCheckbox) {
      console.log("No form elements found, form might not be loaded yet");
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

console.log("Updated form with preferences:", {
    necessary: true,
    marketing: marketingCheckbox?.checked,
    personalization: personalizationCheckbox?.checked,
    analytics: analyticsCheckbox?.checked,
    DoNotShare: doNotShareCheckbox?.checked
});
console.log(" UPDATE PREFERENCE  ENDS___")

}

// Modify initialize function
async function initialize() {
  console.log("INITIALIZATION STARTS");
  
  try {
      // Get visitor session token first
      const token = await getVisitorSessionToken();
      if (!token) {
          console.error("Failed to get visitor session token. Retrying in 2 seconds...");
          // Retry after a delay
          setTimeout(initialize, 2000);
          return;
      }
      
      // Store token in localStorage if not already there
      if (!localStorage.getItem('visitorSessionToken')) {
          localStorage.setItem('visitorSessionToken', token);
      }

      // Load and apply saved preferences
      const preferences = await loadAndApplySavedPreferences();
      
      // Only proceed with normal initialization if no preferences
      if (!preferences || !localStorage.getItem("consent-given")) {
          await scanAndBlockScripts();
          await initializeBannerVisibility();
      }

      // Always load these
      await loadConsentStyles();
      await detectLocationAndGetBannerType();

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
      console.error("Error during initialization:", error);
      // Retry initialization after a delay if there was an error
      setTimeout(initialize, 2000);
  }
  
  console.log("INITIALIZATION ENDS");
}
// Add to your window exports
window.loadAndApplySavedPreferences = loadAndApplySavedPreferences;
window.updatePreferenceForm = updatePreferenceForm;
function blockAllInitialRequests() {
  const originalFetch = window.fetch;
  window.fetch = function (...args) {
      const url = args[0];
      if (initialBlockingEnabled && isSuspiciousResource(url)) {
          
          return Promise.resolve(new Response(null, { status: 204 }));
      }
      return originalFetch.apply(this, args);
  };
  
  const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      
      xhr.open = function(method, url) {
        if (initialBlockingEnabled && isSuspiciousResource(url)) {
          
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
          if (name === 'src' && initialBlockingEnabled && isSuspiciousResource(value)) {
              
              return;
          }
          return originalSetAttribute.apply(this, arguments);
      };
      return img;
  };
  }   



function initializeAll() {
  if (isInitialized) {
    
    return;
  }
  
  
  // Block everything first
  blockAllInitialRequests();
  blockAllScripts();
  
  // Then load state and initialize banner
  loadConsentState().then(() => {
    initializeBanner();
    
    isInitialized = true;
  });
 }
    
         
    
    
    
    
   



})();

   
   

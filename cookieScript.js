
(async function () {



    const existing_Scripts = [];
    let isLoadingState = false;
    let consentState = {};
    let observer;
    let isInitialized = false;
    const blockedScripts = [];
    let currentBannerType = null;
    let country =null;
    let categorizedScripts=null;  
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
    
/*BANNER */

function attachBannerHandlers() {
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
    // Update necessary checkbox
if (necessaryCheckbox) {
    necessaryCheckbox.checked = true;
    necessaryCheckbox.disabled = true; // Always disabled
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
        await restoreAllowedScripts(preferences);
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
        scanAndBlockScripts();
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
          Analytics: analyticsCheckbox?.checked || false
          
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
          checkAndBlockNewScripts(); 
        } else {
          restoreAllowedScripts(preferences); // Unblock scripts if checkbox is unchecked
        }
        await saveConsentState(preferences);
      
        hideBanner(ccpaBanner);
        hideBanner(mainConsentBanner);
        console.assertLOG
      });
    }
  
    // Cancel button handler
    if (cancelButton) {
      cancelButton.addEventListener("click", function(e) {
        e.preventDefault();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
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


// async function saveConsentState(preferences) {    
  
//     const clientId = getClientIdentifier();
//     const visitorId = localStorage.getItem("visitorId");
//     const policyVersion = "1.2";
//     const timestamp = new Date().toISOString();


//    try {
//     const consentPreferences = buildConsentPreferences(preferences, country, timestamp);  
//        const { key, iv } = await EncryptionUtils.generateKey();
//        const encryptionKey ={key: key, iv:iv}
        
//     const encryptedVisitorId = await EncryptionUtils.encrypt(visitorId, key, iv);
    


//     const encryptedPreferences = await EncryptionUtils.encrypt(JSON.stringify(consentPreferences),key, iv);
    


//     await storeEncryptedConsent(encryptedPreferences, key,iv, timestamp);
  
    
  
  
//     const sessionToken = localStorage.getItem('visitorSessionToken');
//     if (!sessionToken) {
//       console.error("Failed to retrieve authentication token.");
//       return;
//     }
//     console.log("called function buildPayload ");

  
//     const payload = buildPayload({
//       clientId,
//       encryptedVisitorId,
//       encryptedPreferences,
//       encryptionKey,
//       policyVersion,
//       timestamp,
//       country
//     });
//     console.log("called https://cb-server.web-8fb.workers.dev/api/cmp/consent ");
//     console.log("payload", payload);
//     console.log("SAVE CONSENT STATE FINISHES..");
//     try {
//       const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//           "Authorization": `Bearer ${sessionToken}`,
//         },
//         body: JSON.stringify(payload),
//       });
  
//       const text = await response.text();
//       console.log("Consent section response:", text);
//     } catch (error) {
//       console.error("Error sending consent data:", error);
//     }
      
//    } catch (error) {
//     console.log(error)
//    }
//   }  
  

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
      DoNotShare: preferences.DoNotShare || false,
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
        DoNotShare: preferences.DoNotShare || false,
        lastUpdated: timestamp,
        country
      }
    };
  }
  
//  async function storeEncryptedConsent(encryptedPreferences, key,iv, timestamp) {

//     console.log("inside store encrpted data",encryptedPreferences)
//     localStorage.setItem("consent-given", "true");
//     localStorage.setItem("consent-preferences", JSON.stringify({
//       encryptedData: encryptedPreferences,
//       iv: Array.from(iv),
//       key: Array.from(new Uint8Array(key))
//     }));
   
//     localStorage.setItem("consent-policy-version", "1.2");
//   }
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
        return url?.trim().replace(`/^https?:///`, '').replace(`//$/`, '');
        }
    
    function createPlaceholder(originalScript, category = "uncategorized") { 
        const placeholder = document.createElement("script"); 
        placeholder.type = "text/plain"; 
        placeholder.setAttribute("data-category", category); 
        placeholder.setAttribute("data-original-src", originalScript.src || "inline"); 
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
        const scripts = document.querySelectorAll("script[src]");
        const inlineScripts = document.querySelectorAll("script:not([src])"); 
        const categorizedScripts = await loadCategorizedScripts();
    
        // Normalize and extract categories
        const normalizedCategorized = categorizedScripts?.map(s => {
            // Get categories from data-category attribute
            const scriptElement = document.createElement('div');
            scriptElement.innerHTML = s.content;
            const scriptTag = scriptElement.querySelector('script');
            const categories = scriptTag ? scriptTag.getAttribute('data-category') : null;
    
            return {
                ...s,
                normalizedSrc: normalizeUrl(s.src),
                normalizedContent: s.content?.trim(),
                categories: categories ? categories.split(',').map(c => c.trim()) : []
            };
        });
    
        console.log("Normalized scripts with categories:", normalizedCategorized);
    
        scripts.forEach(script => {
            const normalizedSrc = normalizeUrl(script.src);
            const matched = normalizedCategorized?.find(s => s.normalizedSrc === normalizedSrc);
    
            if (matched) {
                console.log("Matched script:", matched);
                // Use the categories from the matched script
                const scriptCategories = matched.categories.join(',');
                console.log("Categories for script:", scriptCategories);
    
                const placeholder = createPlaceholder(script, scriptCategories);
                if (placeholder) {
                    script.parentNode.replaceChild(placeholder, script);
                    existing_Scripts.push(placeholder);
                    console.log("Blocked script", script.src, "with categories:", scriptCategories);
                } else {
                    console.error("Could not create placeholder for:", script.src);
                }
            } else {
                // Rest of your existing code for pattern matching
                const patternCategory = findCategoryByPattern(script.src);
                if (patternCategory) {
                    const placeholder = createPlaceholder(script, patternCategory);
                    if (placeholder) {
                        script.parentNode.replaceChild(placeholder, script);
                        existing_Scripts.push(placeholder);
                        console.log("Blocked script", script.src);
                    } else {
                        console.error("Could not create placeholder for:", script.src);
                    }
                }
            }
        });
    
        inlineScripts.forEach(script => { 
          const content = script.textContent.trim().replace(/\s+/g, ''); const matched = normalizedCategorized.find(s => s.normalizedContent === content);
          if (matched) {
              script.setAttribute("data-category", matched.category);
            } else {
              const patternCategory = findCategoryByPattern(content);
              if (patternCategory) {
                const placeholder = createPlaceholder(script, patternCategory);
                script.parentNode.replaceChild(placeholder, script);
                existing_Scripts.push(placeholder);
      console.log("blocked script",script.src);

              }
            }
          });
              

  }

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

  // Normalize preferences keys to lowercase
  const normalizedPrefs = Object.fromEntries(
    Object.entries(preferences).map(([key, value]) => [key.toLowerCase(), value])
  );

  console.log("Existing Scripts", existing_Scripts);

  existing_Scripts?.forEach(placeholder => {
    const categoryAttr = placeholder.getAttribute("data-category");
    if (!categoryAttr) {
      console.log("Script missing data-category attribute, skipping...");
      return;
    }

    const categories = categoryAttr.split(",").map(c => c.trim().toLowerCase());
    const isAllowed = categories.some(cat => normalizedPrefs[cat] === true);

    console.log("category", categoryAttr);
    console.log("normalized preference", normalizedPrefs);
    console.log("isAllowed", isAllowed);

    if (isAllowed) {
      const script = document.createElement("script");
      const originalSrc = placeholder.getAttribute("data-original-src");

      if (originalSrc) {
        script.src = originalSrc;
        console.log("Script src", originalSrc);

        // 🎯 Detect Google Analytics (gtag.js) script using a regex pattern.
        const gtagPattern = /googletagmanager\.com\/gtag\/js/i;
        if (gtagPattern.test(originalSrc)) {
          console.log("Detected GA script, hooking into consent update");

          // Define a helper function to update GA consent
          function updateGAConsent() {
            if (typeof gtag === "function") {
              console.log("Updating GA consent settings...");
              gtag('consent', 'update', {
                'ad_storage': normalizedPrefs.marketing ? 'granted' : 'denied',
                'analytics_storage': normalizedPrefs.analytics ? 'granted' : 'denied',
                'ad_personalization': normalizedPrefs.marketing ? 'granted' : 'denied',
                'ad_user_data': normalizedPrefs.marketing ? 'granted' : 'denied'
              });
            } else {
              console.warn("gtag is not defined even after GA script loaded.");
            }
          }
          
          // If the GA script is still loading, update consent in the onload handler
          script.onload = () => {
            updateGAConsent();
          };

          // Also try to update immediately if gtag is already available
          if (typeof gtag === "function") {
            updateGAConsent();
          } else {
            console.warn("gtag not defined at restoration time; will update on load.");
          }
        }
        



      } else {
        // For inline scripts, simply copy the text content.
        script.textContent = placeholder.textContent || "";
      }

      // Restore attributes: type, async, defer, and data-category
      const type = placeholder.getAttribute("type");
      if (type) script.setAttribute("type", type);
      if (placeholder.hasAttribute("async")) script.async = true;
      if (placeholder.hasAttribute("defer")) script.defer = true;
      
      const dataCategory = placeholder.getAttribute("data-category");
      if (dataCategory) script.setAttribute("data-category", dataCategory);
      
      // Replace the placeholder with the restored script
      placeholder.parentNode?.replaceChild(script, placeholder);
    }
  });

  console.log("RESTORE ENDS");
}

          

  /* INITIALIZATION */
  async function getVisitorSessionToken() {
    try {
        // Get or create visitor ID
        const visitorId = await getOrCreateVisitorId();
        
        // Get cleaned site name
        const siteName = await  cleanHostname(window.location.hostname);
        
        // Check if we have a valid token in localStorage
        let token = localStorage.getItem('visitorSessionToken');
        
        // If we have a token and it's not expired, return it
        if (token && !isTokenExpired(token)) {
            console.log("Token is in localstorage")
            return token;
        }

        // Request new token from server
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
            throw new Error('Failed to get visitor session token');
        }

        const data = await response.json();
        
        // Store the new token
        localStorage.setItem('visitorSessionToken', data.token);
        
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
      // Load and apply saved preferences first
      const preferences = await loadAndApplySavedPreferences();
      
      // Only proceed with normal initialization if no preferences
      if (!preferences || !localStorage.getItem("consent-given")) {
          await scanAndBlockScripts();
          await initializeBannerVisibility();
      }

      // Always load these
      await loadConsentStyles();
      await getVisitorSessionToken();
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

   
   

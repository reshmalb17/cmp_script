
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

    const suspiciousPatterns = [ { pattern: /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview/i, category: "analytics" }, { pattern: /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough/i, category: "marketing" }, { pattern: /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i, category: "personalization" } ];


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

async function generateKey() {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const exportedKey = await crypto.subtle.exportKey("raw", key);
    console.log('Exported key length:', exportedKey.byteLength); // Log key length
    return { secretKey: new Uint8Array(exportedKey), iv }; // Convert to Uint8Array
}

  // Add these two functions here
async function importKey(rawKey) {
    return await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

async function decryptData(encrypted, key, iv) {
    const encryptedBuffer = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encryptedBuffer
    );
    return new TextDecoder().decode(decrypted);
}
async function encryptData(data, key, iv) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    // Ensure the key is a Uint8Array
    const keyArray = new Uint8Array(key);
    console.log('Key array length:', keyArray.length); // Log key array length

    const importedKey = await crypto.subtle.importKey(
        "raw",
        keyArray, // Use the Uint8Array
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        importedKey,
        encodedData
    );
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

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
        checkAndBlockNewScripts();
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


async function saveConsentState(preferences) {    
  
    const clientId = getClientIdentifier();
    const visitorId = localStorage.getItem("visitorId");
    const policyVersion = "1.2";
    const timestamp = new Date().toISOString();


   try {
    const consentPreferences = buildConsentPreferences(preferences, country, timestamp);  
  

        const encryptionKey = await generateKey();    


    const encryptedVisitorId = await encryptData(visitorId, encryptionKey.secretKey, encryptionKey.iv);
    


    const encryptedPreferences = await encryptData(JSON.stringify(consentPreferences), encryptionKey.key, encryptionKey.iv);
    


    await storeEncryptedConsent(encryptedPreferences, encryptionKey, timestamp);
  
    
  
  
    const sessionToken = localStorage.getItem('visitorSessionToken');
    if (!sessionToken) {
      console.error("Failed to retrieve authentication token.");
      return;
    }
    console.log("called function buildPayload ");

  
    const payload = buildPayload({
      clientId,
      encryptedVisitorId,
      encryptedPreferences,
      encryptionKey,
      policyVersion,
      timestamp,
      country
    });
    console.log("called https://cb-server.web-8fb.workers.dev/api/cmp/consent ");
  
    try {
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
    } catch (error) {
      console.error("Error sending consent data:", error);
    }
      
   } catch (error) {
    console.log(error)
   }
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
  
 async function storeEncryptedConsent(encryptedPreferences, encryptionKey, timestamp) {
    console.log("inside store encrpted data",encryptedPreferences)
    localStorage.setItem("consent-given", "true");
    localStorage.setItem("consent-preferences", JSON.stringify({
      encryptedData: encryptedPreferences,
      iv: Array.from(encryptionKey.iv),
      key: Array.from(new Uint8Array(encryptionKey.secretKey))
    }));
   
    localStorage.setItem("consent-policy-version", "1.2");
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
    

async function scanAndBlockScripts() { 
    console.log("inside scan and block");
          const scripts = document.querySelectorAll("script[src]");
          const inlineScripts = document.querySelectorAll("script:not([src])"); 
           const categorizedScripts = await loadCategorizedScripts();

             const normalizedCategorized = categorizedScripts?.map(s => ({ ...s, normalizedSrc: normalizeUrl(s.src), normalizedContent: s.content?.trim() }));

             scripts.forEach(script => {
             const normalizedSrc = normalizeUrl(script.src); 
            const matched = normalizedCategorized?.find(s => s.normalizedSrc === normalizedSrc);
              if (matched) {
                const patternCategory = findCategoryByPattern(script.src);
                script.setAttribute("data-category", matched.category);
                const placeholder = createPlaceholder(script, patternCategory);
                if (placeholder) {
                    script.parentNode.replaceChild(placeholder, script);
                    existing_Scripts.push(placeholder);
            console.log("blocked script",script.src);


                  } else {
                    console.error("Could not create placeholder for:", script.src);
                  }
                
              } 
              else {
                const patternCategory = findCategoryByPattern(script.src);
                if (patternCategory) {
                  const placeholder = createPlaceholder(script, patternCategory);
                  if (placeholder) {
                    script.parentNode.replaceChild(placeholder, script);
                    existing_Scripts.push(placeholder);
                  console.log("blocked script",script.src);

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
    console.log(" LOAD CONSENT STATE STARTS")

            if (isLoadingState) {
              
              return;
           }
              isLoadingState = true;
          
             const consentGiven = localStorage.getItem("consent-given");
              
              if (consentGiven === "true") {
                try {
                    const savedPreferences = JSON.parse(localStorage.getItem("consent-preferences"));
                    if (savedPreferences?.encryptedData) {
                        const decryptedData = await decryptData(
                            savedPreferences.encryptedData,
                            await importKey(Uint8Array.from(savedPreferences.key)),
                            Uint8Array.from(savedPreferences.iv)
                        );
                        consentState = JSON.parse(decryptedData);
                        consentState = {
                          Necessary: consentState.Necessary || true,
                          Marketing: consentState.Marketing || false,
                          Personalization: consentState.Personalization || false,
                          Analytics: consentState.Analytics || false,
                          ccpa: {
                              doNotShare: consentState.ccpa?.DoNotShare || false // Safely access doNotShare
                          }
                      };
        
                        
              // Update checkbox states if they exist
                 const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]')
                 const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]')
                 const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]')
                 const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]')
                 const doNotShareCheckbox = document.getElementById('[data-consent-id="do-not-share-checkbox"]');
      
      
      
        
                        if (necessaryCheckbox) {
                          necessaryCheckbox.checked = true; // Always true
                          necessaryCheckbox.disabled = true; // Disable the necessary checkbox
                        }
      
                
        
          
                        if (necessaryCheckbox) necessaryCheckbox.checked = true; // Always true
                        if (marketingCheckbox) marketingCheckbox.checked = consentState.Marketing || false;
                        if (personalizationCheckbox) personalizationCheckbox.checked = consentState.Personalization || false;
                        if (analyticsCheckbox) analyticsCheckbox.checked = consentState.Analytics || false;
                        if (doNotShareCheckbox) doNotShareCheckbox.checked = consentState.ccpa.DoNotShare || false;
                    }
                } catch (error) {
                    console.error("Error loading consent state:", error);
                    consentState = { 
                        Necessary: true,
                        Marketing: false,
                        Personalization: false,
                        Analytics: false ,
                        ccpa: { doNotShare: false } 
                    };
                }
            } else {
                  consentState = { 
                     Necessary: true,
                     Marketing: false,
                     Personalization: false,
                     Analytics: false ,
                     ccpa: { doNotShare: false } 
            };
          }
          
            
              
            
              isLoadingState = false;
    console.log(" LOAD CONSENT STATE ENDS")

          }
                
  async function restoreAllowedScripts(preferences) {
    console.log(" RESTORE STARTS")



    existing_Scripts?.forEach(placeholder => {
      const category = placeholder.getAttribute("data-category") ;
  
      if (preferences[category]== true) {
         console.log("unblocked script with category",category)
        const script = document.createElement("script");
        const originalSrc = placeholder.getAttribute("data-src");
  
        // External script
        if (originalSrc) {
          script.src = originalSrc;
        } else {
          // Inline script
          script.textContent = placeholder.textContent || "";
        }
  
        // Restore any relevant attributes if needed
        const type = placeholder.getAttribute("data-type");
        if (type) script.setAttribute("type", type);
  
        placeholder.parentNode?.replaceChild(script, placeholder);
      }
    });
    console.log(" RESTORE ENDS")

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

 async function initialize() {

    console.log(" INITIALIZATION STARTS")
      await scanAndBlockScripts();
      await getVisitorSessionToken();   
      await detectLocationAndGetBannerType();
      await loadConsentState();   
      
     hideBanner(document.getElementById("consent-banner"));
     hideBanner(document.getElementById("initial-consent-banner"));
     hideBanner(document.getElementById("main-banner"));
     hideBanner(document.getElementById("main-consent-banner"));
     hideBanner(document.getElementById("simple-consent-banner"));
    
     await initializeBannerVisibility();
 
  
   
     attachBannerHandlers();
    console.log(" INITIALIZATION STARTS ENDS")


     
   }
   


window.loadConsentState = loadConsentState;
window.scanAndBlockScripts = scanAndBlockScripts;
window.initializeBanner= initializeBanner;
window.attachBannerHandlers = attachBannerHandlers;
window.showBanner = showBanner;
window.hideBanner = hideBanner;
window.decryptData = decryptData;   
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

document.addEventListener('DOMContentLoaded',  initialize);



     
         
    
    
    
    
   



})();

   
   

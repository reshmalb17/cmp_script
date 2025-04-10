(async function () {
  // Configuration object
const CONFIG = {
  maxRetries: 5,
  baseUrl: 'https://cb-server.web-8fb.workers.dev',
  retryDelay: 2000
};
    let isLoadingState = false;
    let consentState = {};
    let observer;
    let isInitialized = false;
    const blockedScripts = [];
    let currentBannerType = null;
    let country =null;
    let visitorSessionToken = null;
    let cookieMetadata = new Map();
    const cookiePatterns = {
      necessary: [
        /^PHPSESSID$/,
        /^wordpress_logged_in/,
        /^wp-settings/,
        /^wp-settings-time/,
        /^wordpress_test_cookie$/,
        /^csrf_token$/,
        /^session_id$/,
        /^auth_token$/,
        /^_cf_bm$/,
        /^_cf_logged_in$/,
        /^mbox$/,
        /^_uetsid$/,
        /^_uetvid$/,
        /^sparrow_id$/,
        /^_hjSessionUser_/,
        /^kndctr_.*$/
      ],
      marketing: [
        // Google Ads
        /^_ga$/,
        /^_gid$/,
        /^_gcl_au$/,
        /^_gcl_dc$/,
        /^_gcl_gb$/,
        /^_gcl_hk$/,
        /^_gcl_ie$/,
        /^_gcl_sg$/,
        // Facebook/Meta
        /^_fbp$/,
        /^_fbc$/,
        /^fr$/,
        /^tr$/,
        // LinkedIn
        /^li_oatml$/,
        /^li_sugr$/,
        /^bcookie$/,
        // HubSpot
        /^hubspotutk$/,
        /^__hs_opt_out$/,
        /^__hs_do_not_track$/,
        // Zoho
        /^zohocsrftoken$/,
        /^zohosession$/,
        // Webflow
        /^wf_session$/,
        /^wf_analytics$/,
        // General marketing patterns
        /^ads/,
        /^advertising/,
        /^marketing/,
        /^tracking/,
        /^campaign/,
        /^cfz_facebook-pixel$/,
        /^cfz_reddit$/,
        /^_biz_flagsA$/,
        /^_biz_nA$/,
        /^_biz_pendingA$/,
        /^_biz_uid$/,
        /^_hp5_/,
        /^_mkto_trk$/
      ],
      analytics: [
        // Google Analytics
        /^_ga$/,
        /^_gid$/,
        /^_gat$/,
        /^_gat_/,
        // HubSpot Analytics
        /^__hs_initial_opt_in$/,
        /^__hs_initial_opt_out$/,
        // General analytics patterns
        /^analytics/,
        /^stats/,
        /^metrics/,
        /^AMCV_.*$/,
        /^CF_VERIFIED_DEVICE.*$/
      ],
      personalization: [
        /^user_preferences/,
        /^theme_preference/,
        /^language_preference/,
        /^font_size/,
        /^color_scheme/,
        /^user_settings/,
        /^preferences/,
        /^OptanonConsent$/,
        /^_hssc$/,
        /^_hstc$/,
        /^hubspotutk$/,
        /^_pk_ses/,
        /^_pk_id/,
        /^_pk_ref/,
        /^_cfuvid$/
      ]
    };
    let initialBlockingEnabled = true;  

    async function blockAllScripts() {
      try {
        blockMetaFunctions();
        blockAnalyticsRequests();
        await scanAndBlockScripts();
        blockDynamicScripts();
        createPlaceholderScripts();
        
        if (!consentState.marketing) {
          await blockMarketingScripts();
        }
        if (!consentState.personalization) {
          await blockPersonalizationScripts();
        }
        if (!consentState.analytics) {
          await blockAnalyticsScripts();
        }
      } catch (error) {
        console.error("Error in blockAllScripts:", error);
        // Fallback to basic blocking if advanced blocking fails
        blockMetaFunctions();
        blockAnalyticsRequests();
      }
    }
    

 // Function to get visitor session token
    async function getVisitorSessionToken() {
        try {
            // Get or create visitor ID
            const visitorId = await getOrCreateVisitorId();
            
            // Get cleaned site name
            const siteName = cleanHostname(window.location.hostname);
            
            // Check if we have a valid token in localStorage
            let token = localStorage.getItem('visitorSessionToken');
            
            // If we have a token and it's not expired, return it
            if (token && !isTokenExpired(token)) {
                return token;
            }

            // Request new token from server
            const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Type': 'application/json',
                    'Origin': window.location.origin
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
            if (!data.token) {
              console.error('Invalid token response:', data);
              throw new Error('Invalid token response');
            }
            
            
            // Store the new token
            localStorage.setItem('visitorSessionToken', data.token);
            
            return data.token;
        } catch (error) {
      
            const errorData = await response.json().catch(() => ({}));
            console.error('Failed to get visitor session token:', errorData);
            return null;
        }
    }
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
function cleanHostname(hostname) {
  try {
    let cleaned = hostname.replace(/^www\./, '');
    cleaned = cleaned.split('.')[0];
    console.log("Cleaned hostname:", cleaned);
    return cleaned;
  } catch (error) {
    console.error("Error cleaning hostname:", error);
    return hostname;
  }
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




// Function to detect location and get banner type
async function detectLocationAndGetBannerType() {
  try {
    console.log("Detecting location and getting banner type...");
    const sessionToken = await getVisitorSessionToken();
    if (!sessionToken) {
      console.error('Failed to get valid session token');
      return { bannerType: 'GDPR', country: null }; // Default fallback
    }

    const response = await fetch('https://cb-server.web-8fb.workers.dev/api/cmp/detect-location', {
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
        'Content-Type': 'application/json',
        'Origin': window.location.origin
      },
      mode: 'cors',
      credentials: 'include'
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('Failed to load banner type:', response.status, response.statusText, errorData);
      return { bannerType: 'GDPR', country: null }; // Default fallback
    }

    const data = await response.json();
    console.log("Location data received:", data);
    
    if (!data.bannerType || !data.country) {
      console.error('Invalid location data format:', data);
      return { bannerType: 'GDPR', country: null }; // Default fallback
    }

    return {
      bannerType: data.bannerType,
      country: data.country
    };
  } catch (error) {
    console.error('Error loading location data:', error);
    return { bannerType: 'GDPR', country: null }; // Default fallback
  }
}



// Function to load categorized scripts
async function loadCategorizedScripts() {
  try {
    console.log("Loading categorized scripts...");
    const sessionToken = await getVisitorSessionToken();
    if (!sessionToken) {
      console.warn("No session token available for loading categorized scripts");
      return null;
    }

    const response = await fetch('https://cb-server.web-8fb.workers.dev/api/cmp/script-categories', {
      headers: {
        'Authorization': `Bearer ${sessionToken}`,
        'Content-Type': 'application/json',
        'Origin': window.location.origin
      },
      mode: 'cors',
      credentials: 'include'
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('Failed to load categorized scripts:', errorData);
      return null;
    }

    const data = await response.json();
    console.log("Categorized scripts data received:", data);

    if (!data.scripts || !Array.isArray(data.scripts)) {
      console.error('Invalid script data format:', data);
      return null;
    }

    // Validate and filter scripts
    const validScripts = data.scripts.filter(script => {
      if (!script.src || typeof script.src !== 'string') {
        console.warn('Invalid script entry:', script);
        return false;
      }
      return true;
    });

    console.log(`Loaded ${validScripts.length} valid scripts`);
    return validScripts;
  } catch (error) {
    console.error('Error loading categorized scripts:', error);
    return null;
  }
}


    async function loadConsentState() {
      if (isLoadingState) {
        
        return;
     }
        isLoadingState = true;
    
        blockAllInitialRequests();
        blockAllScripts();
        
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
                    necessary: consentState.necessary || true,
                    marketing: consentState.marketing || false,
                    personalization: consentState.personalization || false,
                    analytics: consentState.analytics || false,
                    ccpa: {
                        doNotShare: consentState.ccpa?.doNotShare || false // Safely access doNotShare
                    }
                };
  
                  
                  // Update checkbox states if they exist
                  const necessaryCheckbox = document.getElementById("necessary-checkbox");
                  const marketingCheckbox = document.getElementById("marketing-checkbox");
                  const personalizationCheckbox = document.getElementById("personalization-checkbox");
                  const analyticsCheckbox = document.getElementById("analytics-checkbox");
                  const doNotShareCheckbox = document.getElementById("do-not-share-checkbox");
  
                  if (necessaryCheckbox) {
                    necessaryCheckbox.checked = true; // Always true
                    necessaryCheckbox.disabled = true; // Disable the necessary checkbox
                  }
    
                  if (necessaryCheckbox) necessaryCheckbox.checked = true; // Always true
                  if (marketingCheckbox) marketingCheckbox.checked = consentState.marketing || false;
                  if (personalizationCheckbox) personalizationCheckbox.checked = consentState.personalization || false;
                  if (analyticsCheckbox) analyticsCheckbox.checked = consentState.analytics || false;
                  if (doNotShareCheckbox) doNotShareCheckbox.checked = consentState.ccpa.doNotShare || false;
              }
          } catch (error) {
              console.error("Error loading consent state:", error);
              consentState = { 
                  necessary: true,
                  marketing: false,
                  personalization: false,
                  analytics: false ,
                  ccpa: { doNotShare: false } 
              };
          }
      } else {
            consentState = { 
               necessary: true,
               marketing: false,
               personalization: false,
               analytics: false ,
               ccpa: { doNotShare: false } 
      };
    }
    
        initialBlockingEnabled = !consentState.analytics;
        
        // Always scan and block on initial load
        blockAllScripts();
        
        // If analytics are accepted, unblock after initial scan
        if (!initialBlockingEnabled) {
            unblockScripts();
        }
        isLoadingState = false;
    }
    
    async function initializeBannerVisibility() {
      //const request = new Request(window.location.href);
      const locationData = await detectLocationAndGetBannerType();  
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
// Function to initialize the CMP
async function initialize() {
  try {
    console.log("Initializing CMP...");

    // Initialize cookie metadata storage
    cookieMetadata = new Map();
    
    // First, ensure we have a valid session token
    const sessionToken = await getVisitorSessionToken();
    if (!sessionToken) {
      console.error('Failed to initialize: Could not get valid session token');
      return;
    }
    console.log("Session token obtained successfully");

    // Scan existing cookies
    await scanExistingCookies();
    
    // Hide all banners initially
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner"));
    hideBanner(document.getElementById("main-banner"));
    hideBanner(document.getElementById("main-consent-banner"));
    hideBanner(document.getElementById("simple-consent-banner"));

    // Load consent state and initialize banner visibility
    await loadConsentState();
    await initializeBannerVisibility();

    // Check for main banners
    const hasMainBanners = document.getElementById("consent-banner") || document.getElementById("initial-consent-banner");
    
    if (!hasMainBanners) {
      console.log("No main banners found, initializing simple banner");
      initializeSimpleBanner();
    } else {
      console.log("Main banners found, initializing banner visibility");
      await initializeBannerVisibility();
    }
    
    // Attach handlers and start monitoring
    attachBannerHandlers();
    monitorCookieChanges();
    
    console.log("CMP initialization completed successfully");
  } catch (error) {
    console.error("Error in initializing script:", error);
  }
}

      document.addEventListener('DOMContentLoaded', initialize);
  
    async function initializeBlocking() {
        blockAllScripts();
        const consentGiven = localStorage.getItem("consent-given");
        const consentBanner = document.getElementById("consent-banner");
        const ccpaBanner = document.getElementById("initial-consent-banner");
        
      
        if (consentGiven === "true") {
          return; // Exit early if consent is already given
        }
        const locationData = await getLocationData();
      
        if (consentGiven === "true") {
          try {
            const savedPreferences = JSON.parse(localStorage.getItem("consent-preferences"));
            if (savedPreferences?.encryptedData) {
              const decryptedData = await decryptData(
                savedPreferences.encryptedData,
                await importKey(Uint8Array.from(savedPreferences.key)),
                Uint8Array.from(savedPreferences.iv)
              );
              const preferences = JSON.parse(decryptedData);
              initialBlockingEnabled = !preferences.analytics;
      
              // Show the appropriate banner based on preferences
              if (initialBlockingEnabled) {
                blockAllScripts();
                showBanner(consentBanner); // Show GDPR banner if blocking is enabled
              } else {
                unblockScripts();
                hideBanner(consentBanner); // Hide GDPR banner if blocking is disabled
              }
            }
          } catch (error) {
            console.error("Error loading consent state:", error);
            initialBlockingEnabled = true;
            showBanner(consentBanner); // Show GDPR banner if there's an error
          }
        } else {
          // No consent given, show GDPR banner and enable blocking
          initialBlockingEnabled = true;
          showBanner(consentBanner);
          blockAllScripts();
        }
      }
  
  
    // Move createPlaceholder function outside of scanAndBlockScripts
    async function createPlaceholder(script, category) {
        const placeholder = document.createElement('script');
        placeholder.type = 'text/placeholder';
        placeholder.dataset.src = script.src;
        placeholder.dataset.async = script.async || false;
        placeholder.dataset.defer = script.defer || false;
        placeholder.dataset.type = script.type || 'text/javascript';
        placeholder.dataset.crossorigin = script.crossOrigin || '';
    
        if (category) {
            placeholder.dataset.category = category; // Store the script category
        }
    
        return placeholder;
    }
    
  
  async function scanAndBlockScripts() {
    const scripts = document.querySelectorAll("script[src]");
    const inlineScripts = document.querySelectorAll("script:not([src])");
    
    // Handle external scripts
    scripts.forEach(script => {
        if (isSuspiciousResource(script.src)) {
          console.log("Blocking script:", script.src);
            const placeholder = createPlaceholder(script);
            script.parentNode.replaceChild(placeholder, script);
            blockedScripts.push(placeholder);
       
        } else {
           
        }
    });
  
    // Handle inline scripts
    inlineScripts.forEach(script => {
        const content = script.textContent;
        if (content.match(/gtag|ga|fbq|twq|pintrk|snaptr|_qevents|dataLayer|plausible/)) {
            
            script.remove();
        } else {
           
        }
    });
  }
  
  async function isSuspiciousResource(url) {
    const suspiciousPatterns = /gtag|analytics|zoho|track|collect|googletagmanager|googleanalytics|metrics|pageview|stat|trackpageview|pixel|doubleclick|adservice|adwords|adsense|connect\.facebook\.net|fbevents\.js|facebook|meta|graph\.facebook\.com|business\.facebook\.com|pixel|quantserve|scorecardresearch|clarity\.ms|hotjar|mouseflow|fullstory|logrocket|mixpanel|segment|amplitude|heap|kissmetrics|matomo|piwik|woopra|crazyegg|clicktale|optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat|olark|purechat|snapengage|liveperson|boldchat|clickdesk|userlike|zopim|crisp|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|moat|integral-marketing|comscore|nielsen|quantcast|adobe|marketo|hubspot|salesforce|pardot|eloqua|act-on|mailchimp|constantcontact|sendgrid|klaviyo|braze|iterable|appsflyer|adjust|branch|kochava|singular|tune|attribution|chartbeat|parse\.ly|newrelic|datadog|sentry|rollbar|bugsnag|raygun|loggly|splunk|elastic|dynatrace|appoptics|pingdom|uptimerobot|statuscake|newrelic|datadoghq|sentry\.io|rollbar\.com|bugsnag\.com|raygun\.io|loggly\.com|splunk\.com|elastic\.co|dynatrace\.com|appoptics\.com|pingdom\.com|uptimerobot\.com|statuscake\.com|clarity|clickagy|yandex|baidu/;
    const isSuspicious = suspiciousPatterns.test(url);
     if (isSuspicious) {
     console.log("Suspicious script detected:", url);
     }
     return isSuspicious;
  }
  

  async function blockAnalyticsScripts() {
    const analyticsPatterns = /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview/i;
    const category = "Analytics";
    const categorizedScripts = await loadCategorizedScripts();
    const blockedScripts = []; // Add this if not already defined globally
    console.log("categorized script Analytics", categorizedScripts);
  
    const scripts = document.querySelectorAll('script[src]');
  
    scripts.forEach(script => {
      const src = script.src;
  
      if (!src) return;
  
      // If categorizedScripts is null, use default pattern
      if (!categorizedScripts) {
        if (analyticsPatterns.test(src)) {
          console.log("Blocking Analytics Script:", src);
          const placeholder = createPlaceholder(script, category);
          script.parentNode.replaceChild(placeholder, script);
          blockedScripts.push(placeholder);
        }
        return;
      }
  
      const matchingEntry = categorizedScripts.find(entry => entry.src === src);
      const isAnalyticsCategory = matchingEntry && matchingEntry.selectedCategories.includes(category);
      const isDefaultAnalyticsScript = !matchingEntry && analyticsPatterns.test(src);
      const isInAnotherCategory = matchingEntry && !matchingEntry.selectedCategories.includes(category);
  
      if ((isAnalyticsCategory || isDefaultAnalyticsScript) && !isInAnotherCategory) {
        console.log("Blocking Analytics Script:", src);
        const placeholder = createPlaceholder(script, category);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  

 async function blockMarketingScripts() {
    const marketingPatterns = /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough/i;
    const category = "Marketing";
    const  categorizedScripts = await loadCategorizedScripts();
    console.log("categorized script Marketing",categorizedScripts);

    const scripts = document.querySelectorAll('script[src]');

    scripts.forEach(script => {
      const src = script.src;
  
      if (!src) return;
  
      // If categorizedScripts is null, use default pattern
      if (!categorizedScripts) {
        if (marketingPatterns.test(src)) {
          console.log("Blocking Analytics Script:", src);
          const placeholder = createPlaceholder(script, category);
          script.parentNode.replaceChild(placeholder, script);
          blockedScripts.push(placeholder);
        }
        return;
      }
  
      const matchingEntry = categorizedScripts.find(entry => entry.src === src);
      const isAnalyticsCategory = matchingEntry && matchingEntry.selectedCategories.includes(category);
      const isDefaultAnalyticsScript = !matchingEntry && marketingPatterns.test(src);
      const isInAnotherCategory = matchingEntry && !matchingEntry.selectedCategories.includes(category);
  
      if ((isAnalyticsCategory || isDefaultAnalyticsScript) && !isInAnotherCategory) {
        console.log("Blocking Analytics Script:", src);
        const placeholder = createPlaceholder(script, category);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  
async function blockPersonalizationScripts() {
    const personalizationPatterns = /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i;
    const category = "Personalization";
    const  categorizedScripts = await loadCategorizedScripts();
    console.log("categorized script Personalization",categorizedScripts);

    const scripts = document.querySelectorAll('script[src]');
   
    scripts.forEach(script => {
      const src = script.src;
  
      if (!src) return;
  
      // If categorizedScripts is null, use default pattern
      if (!categorizedScripts) {
        if (personalizationPatterns.test(src)) {
          console.log("Blocking Analytics Script:", src);
          const placeholder = createPlaceholder(script, category);
          script.parentNode.replaceChild(placeholder, script);
          blockedScripts.push(placeholder);
        }
        return;
      }
  
      const matchingEntry = categorizedScripts.find(entry => entry.src === src);
      const isAnalyticsCategory = matchingEntry && matchingEntry.selectedCategories.includes(category);
      const isDefaultAnalyticsScript = !matchingEntry && personalizationPatterns.test(src);
      const isInAnotherCategory = matchingEntry && !matchingEntry.selectedCategories.includes(category);
  
      if ((isAnalyticsCategory || isDefaultAnalyticsScript) && !isInAnotherCategory) {
        console.log("Blocking Analytics Script:", src);
        const placeholder = createPlaceholder(script, category);
        script.parentNode.replaceChild(placeholder, script);
        blockedScripts.push(placeholder);
      }
    });
  }
  



  
async function unblockScripts(category) {
    blockedScripts.forEach((placeholder, index) => {
        if (placeholder.dataset.category === category) {
            if (placeholder.dataset.src) {
                const script = document.createElement('script');
                script.src = placeholder.dataset.src;
                script.async = placeholder.dataset.async === 'true';
                script.defer = placeholder.dataset.defer === 'true';
                script.type = placeholder.dataset.type;
                if (placeholder.dataset.crossorigin) {
                    script.crossOrigin = placeholder.dataset.crossorigin;
                }

                // Add load event listener
                script.onload = () => {
                    console.log("Loaded script:", script.src);
                    // Reinitialize specific analytics if needed
                    if (script.src.includes('fbevents.js')) {
                        initializeFbq();
                    }
                    // Add other analytics reinitializations as needed
                };

                placeholder.parentNode.replaceChild(script, placeholder);
                blockedScripts.splice(index, 1); // Remove unblocked script from list
            }
        }
    });

    // If all scripts of a category are unblocked, clean up observers
    if (blockedScripts.length === 0) {
        if (observer) observer.disconnect();
        headObserver.disconnect();
    }

    // Restore original functions if needed
    if (category === "Marketing" && window.fbqBlocked) {
        delete window.fbqBlocked;
        loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
    }
}

  
  // Add this new function to restore original functions
  async function restoreOriginalFunctions() {
      if (window.originalFetch) window.fetch = window.originalFetch;
      if (window.originalXHR) window.XMLHttpRequest = window.originalXHR;
      if (window.originalImage) window.Image = window.originalImage;
      
      if (window.fbqBlocked) {
          delete window.fbqBlocked;
          loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
      }
  }
  
async function blockAnalyticsRequests() {
    // Fetch Blocking (Improved)
    const originalFetch = window.fetch;
    window.fetch = function (...args) {
        const url = args[0];
        if (typeof url === "string" && !consentState.analytics && isSuspiciousResource(url)) {
            
            return Promise.resolve(new Response(null, { status: 204, statusText: 'No Content' })); // More robust empty response
        }
        return originalFetch.apply(this, args);
    };
  
   
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const originalOpen = xhr.open;
      
      xhr.open = function(method, url) {
        if (typeof url === "string" && !consentState.analytics && isSuspiciousResource(url)) {
          
          return;
        }
        return originalOpen.apply(xhr, arguments); // Use xhr instead of this
      };
      return xhr;
    };
  }
  
  
  async function blockMetaFunctions() {
    if (!consentState.analytics) {
      if (!window.fbqBlocked) {
        window.fbqBlocked = window.fbq || function () {
          
          window.fbq.queue.push(arguments);
        };
        window.fbqBlocked.queue = [];
        window.fbq = window.fbqBlocked;
        
      }
    } else {
      if (window.fbq === window.fbqBlocked) {
        delete window.fbqBlocked;
        delete window.fbq;
        
        // Direct load without delay
        loadScript("https://connect.facebook.net/en_US/fbevents.js", initializeFbq);
        
      }
    }
  }
  async function initializeFbq() {
    if (window.fbq && window.fbq.queue) {
      window.fbq.queue.forEach(args => window.fbq.apply(null, args));
    }
    
  }
// Flag to control initial blocking
  
 async  function blockAllInitialRequests() {
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
  
  async function getClientIdentifier() {
  return window.location.hostname; // Use hostname as the unique client identifier
  }
  
    async function hashData(data) {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);
      const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
      return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
  
    async function generateKey() {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const exportedKey = await crypto.subtle.exportKey("raw", key);
      return { secretKey: exportedKey, iv };
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
      const importedKey = await crypto.subtle.importKey(
        "raw",
        key,
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
  
  async  function getCookie(name) {
      const cookieString = document.cookie;
      if (!cookieString) return null;
      
      const cookies = Object.fromEntries(
          cookieString.split("; ").map(c => c.split("="))
      );
      
      return cookies[name] || null;
  }
  
 async function scanExistingCookies() {
    console.log('Scanning existing cookies...');
    const cookies = document.cookie.split(';');
    
    cookies.forEach(cookie => {
      try {
        const [name, value] = cookie.split('=').map(part => part.trim());
        if (name) {
          console.log('Processing cookie:', name);
             // Check if cookiePatterns is defined
      if (!cookiePatterns) {
        console.warn("cookiePatterns is not defined, skipping cookie categorization");
        return;
      }
          
          // Determine category based on cookie name
          let category = 'other';
          for (const [cat, patterns] of Object.entries(cookiePatterns)) {
            if (patterns.some(pattern => pattern.test(name))) {
              category = cat;
              break;
            }
          }
  
          // Get cookie attributes
          const attributes = {};
          if (document.cookie.includes(name + '=')) {
            attributes.exists = true;
            const cookieStr = document.cookie.split(';').find(c => c.trim().startsWith(name + '='));
            if (cookieStr) {
              const parts = cookieStr.split(';');
              parts.forEach(part => {
                const [key, val] = part.split('=').map(s => s.trim().toLowerCase());
                if (key === 'expires') attributes.expires = val;
                if (key === 'max-age') attributes.maxAge = parseInt(val);
                if (key === 'secure') attributes.secure = true;
                if (key === 'httponly') attributes.httpOnly = true;
                if (key === 'samesite') attributes.sameSite = val;
              });
            }
          }
  
          window.cookieMetadata.set(name, {
            category: category,
            duration: calculateDuration(new Date(), attributes.expires ? new Date(attributes.expires) : new Date()),
            description: getCookieDescription(name),
            attributes: attributes,
            lastUpdated: new Date().toISOString()
          });
          
          console.log('Added cookie to metadata:', name, category);
        }
      } catch (error) {
        console.error('Error processing cookie:', cookie, error);
      }
    });
    
    console.log('Current cookieMetadata:', window.cookieMetadata);
  }
  
  async function monitorCookieChanges() {
  
    const existingCookies = document.cookie.split(';');
    existingCookies.forEach(cookie => {
      try {
        const cookieInfo = parseCookieString(cookie);
        if (cookieInfo) {
          cookieMetadata.set(cookieInfo.name, {
            duration: cookieInfo.duration,
            description: getCookieDescription(cookieInfo.name),
            attributes: cookieInfo.attributes
          });
        }
      } catch (error) {
        console.error('Error processing existing cookie:', error);
      }
    });
  
    const originalSetCookie = document.__lookupSetter__('cookie');
    
    Object.defineProperty(document, 'cookie', {
      configurable: true,
      set: function(value) {
        try {
          const cookieInfo = parseCookieString(value);
          if (cookieInfo) {
            cookieMetadata.set(cookieInfo.name, {
              duration: cookieInfo.duration,
              description: getCookieDescription(cookieInfo.name),
              attributes: cookieInfo.attributes
            });
          }
        } catch (error) {
          console.error('Error monitoring cookie:', error);
        }
        return originalSetCookie.call(document, value);
      },
      get: document.__lookupGetter__('cookie')
    });
  }
  
 async function parseCookieString(cookieStr) {
    if (!cookieStr) return null;
    
    const parts = cookieStr.split(';');
    const [nameValue] = parts[0].split('=');
    const name = nameValue.trim();
    let duration = 'Session';
    const attributes = {};
  
    for (const part of parts.slice(1)) {
      const [key, value] = part.trim().split('=').map(s => s.trim().toLowerCase());
      
      if (key === 'expires') {
        const expiryDate = new Date(value);
        if (!isNaN(expiryDate.getTime())) {
          const now = new Date();
          duration = calculateDuration(now, expiryDate);
        }
        attributes.expires = value;
      } else if (key === 'max-age') {
        const maxAge = parseInt(value);
        if (!isNaN(maxAge)) {
          duration = convertMaxAgeToDuration(maxAge);
        }
        attributes.maxAge = maxAge;
      } else if (key === 'secure') {
        attributes.secure = true;
      } else if (key === 'httponly') {
        attributes.httpOnly = true;
      } else if (key === 'samesite') {
        attributes.sameSite = value;
      }
    }
  
    return { name, duration, attributes };
  }
  
  // Add these helper functions after the existing cookie-related functions
  function calculateDuration(startDate, endDate) {
    var diff = endDate - startDate;
    
    var seconds = Math.floor(diff / 1000);
    var minutes = Math.floor(seconds / 60);
    var hours = Math.floor(minutes / 60);
    var days = Math.floor(hours / 24);
    var months = Math.floor(days / 30.44); // Average month length
    var years = Math.floor(days / 365.25); // Account for leap years
  
    if (seconds < 60) return seconds + ' seconds';
    if (minutes < 60) return minutes + ' minutes';
    if (hours < 24) return hours + ' hours';
    if (days < 30) return days + ' days';
    if (months < 12) return months + ' months';
    return years + ' years';
  }
  
  function convertMaxAgeToDuration(maxAge) {
    if (maxAge <= 0) return 'Session';
    if (maxAge < 60) return maxAge + ' seconds';
    if (maxAge < 3600) return Math.round(maxAge/60) + ' minutes';
    if (maxAge < 86400) return Math.round(maxAge/3600) + ' hours';
    if (maxAge < 2592000) return Math.round(maxAge/86400) + ' days';
    if (maxAge < 31536000) return Math.round(maxAge/2592000) + ' months';
    return Math.round(maxAge/31536000) + ' years';
  }
  
  
  async function saveConsentState(preferences, country) {
    scanExistingCookies();
    const clientId = getClientIdentifier(); 
    const visitorId = getCookie("visitorId") || crypto.randomUUID();
    const policyVersion = "1.2";
    const timestamp = new Date().toISOString();
    const ip = window.clientIp;
  

    // Initialize cookie data structure
    const cookieData = {
        necessary: [],
        marketing: [],
        personalization: [],
        analytics: [],
        other: [],
        metadata: {}
    };
  
    // Process cookies from cookieMetadata
      console.log('Processing cookieMetadata:', window.cookieMetadata);
      window.cookieMetadata.forEach((value, name) => {
        // Add to metadata
        cookieData.metadata[name] = {
          duration: value.duration,
          description: value.description,
          attributes: value.attributes,
          lastUpdated: value.lastUpdated || timestamp
        };
  
    
    if (cookieMetadata && cookieMetadata.size > 0) {
      cookieMetadata.forEach((value, key) => {
        cookieData.metadata[key] = value;
        
        // Categorize cookies based on patterns
        let categorized = false;
        for (const [category, patterns] of Object.entries(cookiePatterns)) {
          if (patterns.some(pattern => pattern.test(key))) {
            cookieData[category].push(key);
            categorized = true;
            break;
          }
        }
        if (!categorized) {
          cookieData.other.push(key);
        }
      });
    }
  
        // Categorize based on patterns
        let categorized = false;
        for (const [category, patterns] of Object.entries(cookiePatterns)) {
          if (patterns.some(pattern => pattern.test(name))) {
            cookieData[category].push(name);
            categorized = true;
            console.log('Categorized cookie ' + name + ' as ' + category);
            break;
          }
        }
        if (!categorized) {
          cookieData.other.push(name);
          console.log('Categorized cookie ' + name + ' as other');
        }
      });
  
  function getCookieDescription(cookieName) {
    const descriptions = {
      '_hssrc': 'This cookie is set by Hubspot whenever it changes the session cookie. The _hssrc cookie set to 1 indicates that the user has restarted the browser, and if the cookie does not exist, it is assumed to be a new session.',
      '_hssc': 'HubSpot sets this cookie to keep track of sessions and to determine if HubSpot should increment the session number and timestamps in the __hstc cookie.',
      '_ga': 'Google Analytics cookie used to distinguish unique users',
      '_gid': 'Google Analytics cookie used to store and update a unique value for each page visited',
      '_gat': 'Google Analytics cookie used to throttle request rate',
      '_fbp': 'Facebook Pixel cookie used to track conversions and optimize ads',
      '_fbc': 'Facebook Click ID cookie used to track conversions',
      'hubspotutk': 'HubSpot cookie used to keep track of a visitors identity',
      '_hstc': 'HubSpot cookie containing the visitors identity and timestamp',
      '_pk_ses': 'Matomo/Piwik session cookie',
      '_pk_id': 'Matomo/Piwik visitor ID cookie',
      '_pk_ref': 'Matomo/Piwik referrer cookie',
      'PHPSESSID': 'PHP session cookie used to maintain user session',
      'wordpress_logged_in': 'WordPress cookie indicating user login status',
      'wp-settings': 'WordPress user preferences cookie',
      'wp-settings-time': 'WordPress user preferences timestamp cookie',
      'wordpress_test_cookie': 'WordPress test cookie',
      'csrf_token': 'Cross-Site Request Forgery protection cookie',
      'session_id': 'General session management cookie',
      'auth_token': 'Authentication token cookie',
      '_cf_bm': 'Cloudflare bot management cookie',
      '_cf_logged_in': 'Cloudflare logged-in status cookie',
      'mbox': 'Adobe Target cookie',
      '_uetsid': 'Microsoft UET tracking cookie',
      '_uetvid': 'Microsoft UET visitor cookie',
      'sparrow_id': 'Sparrow ID tracking cookie',
      '_hjSessionUser_': 'Hotjar session user cookie',
      'kndctr_': 'Kendo UI counter cookie'
    };
  
    return descriptions[cookieName] || 'No description available';
  }
  
    const consentPreferences = {
      necessary: true, // Always true
      marketing: preferences.marketing || false,
      personalization: preferences.personalization || false,
      analytics: preferences.analytics || false,
      doNotShare: preferences.doNotShare || false, // Add doNotShare preference
      country: country, // Add detected country
      timestamp: timestamp,
      ip: ip,
      cookies: cookieData,
      gdpr: {
        necessary: true,
        marketing: preferences.marketing || false,
        personalization: preferences.personalization || false,
        analytics: preferences.analytics || false,
        lastUpdated: timestamp,
        country: country // Add detected country for GDPR
      },
      ccpa: {
        necessary: true,
        doNotShare: preferences.doNotShare || false,
        lastUpdated: timestamp,
        country: country // Add detected country for CCPA
      }
    };
  
  
  
    // Generate encryption key and encrypt data
    const encryptionKey = await generateKey();
    const encryptedVisitorId = await encryptData(visitorId, encryptionKey.secretKey, encryptionKey.iv);
    const encryptedPreferences = await encryptData(JSON.stringify(consentPreferences), encryptionKey.secretKey, encryptionKey.iv);
  
    // Save to localStorage
    localStorage.setItem("consent-given", "true");
    localStorage.setItem("consent-preferences", JSON.stringify({
        encryptedData: encryptedPreferences,
        iv: Array.from(encryptionKey.iv),
        key: Array.from(new Uint8Array(encryptionKey.secretKey))
    }));
    localStorage.setItem("consent-timestamp", timestamp);
    localStorage.setItem("consent-policy-version", "1.2");
  
    // Prepare payload with encrypted data
    const payload = {
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
        ip: ip,
        
        
      },
      policyVersion,
      timestamp,
      cookies: cookieData,
      country: country,
      bannerType:currentBannerType,
    };
    try {
        const sessionToken =  localStorage.getItem('visitorSessionToken');
        if (!token) {
            console.error("Failed to retrieve authentication token.");
            return;
        }
        const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                'Authorization': `Bearer ${token}`,   
                
            },
            body: JSON.stringify(payload),
        });
  
        const text = await response.text();
        
    } catch (error) {
        console.error("Error sending consent data:", error);
    }
  }
  
  const headObserver = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          
            if (node.tagName === 'SCRIPT' && isSuspiciousResource(node.src)) {
                
                node.remove(); // Remove the script before it runs
            }
        });
    });
  });
  
  headObserver.observe(document.head, { childList: true, subtree: true });
  
 async function blockDynamicScripts() {
    if (observer) observer.disconnect(); // Disconnect previous observer if it exists
    observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.tagName === "SCRIPT" && isSuspiciousResource(node.src)) {
                    console.log("Blocking dynamically added script:", node.src); // Log blocked script
                    node.remove();
                }
                if (node.tagName === "IFRAME" && isSuspiciousResource(node.src)) {
                    //console.log("Blocking dynamically added iframe:", node.src); // Log blocked iframe
                    node.remove();
                }
                // Block dynamically added images (for tracking pixels)
                if (node.tagName === "IMG" && isSuspiciousResource(node.src)) {
                    //console.log("Blocking dynamically added image:", node.src); // Log blocked image
                    node.remove();
                }
            });
        });
    });
  
    observer.observe(document.body, { childList: true, subtree: true });
  }
  
   function createPlaceholderScripts() {
      const allScripts = document.querySelectorAll('script');
      allScripts.forEach(script => {
          if (isSuspiciousResource(script.src)) {
              const placeholder = document.createElement('script');
              placeholder.type = 'text/placeholder'; // Mark as placeholder
              placeholder.dataset.src = script.src; // Store original source
              placeholder.dataset.async = script.async; // Store original async
              script.parentNode.replaceChild(placeholder, script); // Replace with placeholder
              blockedScripts.push(placeholder);
              
          }
      });
  }
  
  function revalidateBlockedScripts() {
    if (!consentState.analytics) {
        
        scanAndBlockScripts();
        blockDynamicScripts();
    }
  }
  
 async function updateConsentState(preferences) {
    
    consentState = preferences;
    initialBlockingEnabled = !preferences.analytics;
    let category;
  
    if (preferences.doNotShare) {
      blockMarketingScripts();
      blockPersonalizationScripts();
      blockAnalyticsScripts();
    } else {
      // Unblock scripts based on user preferences
      if (preferences.marketing) {
        category="Marketing";
        unblockScripts(category); // Unblock marketing scripts if allowed
      }
      if (preferences.personalization) {
        category="Personalization";        
        unblockScripts(category); // Unblock personalization scripts if allowed
      }
      if (preferences.analytics) {

        category="Analytics";        
        unblockScripts(category); 
      }
    }
    
    if (preferences.analytics) {
        
        category="Analytics";        
        unblockScripts(category); 
    } else {
        
        blockAllScripts();
    }
    
    saveConsentState(preferences, currentLocation.country);
  }
  
  async function loadScript(src, callback) {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.onload = callback;
    document.head.appendChild(script);
    
  }
  
 async function initializeBanner() {
    
    
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
    const necessaryCheckbox = document.getElementById("necessary-checkbox");
    const marketingCheckbox = document.getElementById("marketing-checkbox");
    const personalizationCheckbox = document.getElementById("personalization-checkbox");
    const analyticsCheckbox = document.getElementById("analytics-checkbox");
    const doNotShareCheckbox = document.getElementById("do-not-share-checkbox");
  
  
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
            necessary: true,
            marketing: true,
            personalization: true,
            analytics: true,
            doNotShare: false
          };
          
            await updateConsentState(preferences);
            unblockScripts();
            hideBanner(simpleBanner);
            localStorage.setItem("consent-given", "true");
          
          });
        }
      
  
      if (simpleRejectButton) {
        simpleRejectButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Reject button clicked');
          const preferences = {
            necessary: true,
            marketing: false,
            personalization: false,
            analytics: false,
            doNotShare: true
          };
          await updateConsentState(preferences);
          blockAllScripts();
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
          necessary: true,
          marketing: true,
          personalization: true,
          analytics: true
        };
        await updateConsentState(preferences);
        unblockScripts();
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    // Decline button handler
    if (declineButton) {
      declineButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          necessary: true,
          marketing: false,
          personalization: false,
          analytics: false
        };
        await updateConsentState(preferences);
        blockAllScripts();
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
      savePreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const preferences = {
          necessary: true, // Always true
          marketing: marketingCheckbox?.checked || false,
          personalization: personalizationCheckbox?.checked || false,
          analytics: analyticsCheckbox?.checked || false
          
        };
        await updateConsentState(preferences);
        hideBanner(consentBanner);
        hideBanner(mainBanner);
      });
    }
  
    if (saveCCPAPreferencesButton) {
      saveCCPAPreferencesButton.addEventListener("click", async function(e) {
        e.preventDefault();
        const doNotShare = doNotShareCheckbox.checked;
        const preferences = {
          necessary: true, // Always true
          doNotShare: doNotShare // Set doNotShare based on checkbox
        };
        await updateConsentState(preferences);
        
        // Block or unblock scripts based on the checkbox state
        if (doNotShare) {
          blockAllScripts(); // Block all scripts if checkbox is checked
        } else {
          unblockScripts(); // Unblock scripts if checkbox is unchecked
        }
    
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
  
  // Window attachments
  window.loadConsentState = loadConsentState;
  window.blockMetaFunctions = blockMetaFunctions;
  window.blockAllInitialRequests = blockAllInitialRequests;
  window.blockAnalyticsRequests = blockAnalyticsRequests;
  window.scanAndBlockScripts = scanAndBlockScripts;
  window.blockDynamicScripts = blockDynamicScripts;
  window.updateConsentState = updateConsentState;
  window.initializeBanner= initializeBanner;
  window.initializeBlocking = initializeBlocking;
  window.attachBannerHandlers = attachBannerHandlers;
  window.initializeAll = initializeAll;
  window.showBanner = showBanner;
  window.hideBanner = hideBanner;
  window.importKey = importKey;         
  window.decryptData = decryptData;   
  window.unblockScripts = unblockScripts;
  window.createPlaceholderScripts = createPlaceholderScripts;
  window.restoreOriginalFunctions = restoreOriginalFunctions;
  window.loadCategorizedScripts =loadCategorizedScripts;
  window.detectLocationAndGetBannerType = detectLocationAndGetBannerType;
  window.getVisitorSessionToken = getVisitorSessionToken;
  window.isTokenExpired = isTokenExpired;
    window.cleanHostname = cleanHostname;
    window.getOrCreateVisitorId = getOrCreateVisitorId;

  
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
      
      // Set up periodic script checking
      setInterval(revalidateBlockedScripts, 5000);
  })();
  

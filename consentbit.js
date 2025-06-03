(function () {
  // --- Hardcoded Encryption Keys (matching server) ---
  const ENCRYPTION_KEY = "t95w6oAeL1hr0rrtCGKok/3GFNwxzfLxiWTETfZurpI="; // Base64 encoded 256-bit key
  const ENCRYPTION_IV = "yVSYDuWajEid8kDz"; // Base64 encoded 128-bit IV

  // --- Helper functions ---
  function setConsentCookie(name, value, days) {
    let expires = "";
    if (days) {
      const date = new Date();
      date.setTime(date.getTime() + (days*24*60*60*1000));
      expires = "; expires=" + date.toUTCString();
    }
    let cookieString = name + "=" + value + expires + "; path=/; SameSite=Lax";
    if (location.protocol === 'https:') {
      cookieString += "; Secure";
    }
    document.cookie = cookieString;
  }
  function getConsentCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }
  function blockScriptsByCategory() {
    var scripts = document.querySelectorAll('script[data-category]');
    scripts.forEach(function(script) {
      var category = script.getAttribute('data-category');
      if (category && script.type !== 'text/plain') {
        // Handle comma-separated categories
        var categories = category.split(',').map(function(cat) { return cat.trim(); });
        
        // Check if ANY category is necessary or essential (these should never be blocked)
        var hasEssentialCategory = categories.some(function(cat) { 
          var lowercaseCat = cat.toLowerCase();
          return lowercaseCat === 'necessary' || lowercaseCat === 'essential'; 
        });
        
        // Only block if NO categories are essential/necessary
        if (!hasEssentialCategory) {
          script.type = 'text/plain';
          script.setAttribute('data-blocked-by-consent', 'true');
        }
      }
    });
  }
  function enableScriptsByCategories(allowedCategories) {
    var scripts = document.querySelectorAll('script[type="text/plain"][data-category]');
    scripts.forEach(function(oldScript) {
      var category = oldScript.getAttribute('data-category');
      // Handle comma-separated categories
      var categories = category.split(',').map(function(cat) { return cat.trim(); });
      var shouldEnable = categories.some(function(cat) { 
        return allowedCategories.includes(cat); 
      });
      if (shouldEnable) {
        var newScript = document.createElement('script');
        for (var i = 0; i < oldScript.attributes.length; i++) {
          var attr = oldScript.attributes[i];
          if (attr.name === 'type') {
            newScript.type = 'text/javascript';
          } else {
            newScript.setAttribute(attr.name, attr.value);
          }
        }
        if (oldScript.innerHTML) {
          newScript.innerHTML = oldScript.innerHTML;
        }
        oldScript.parentNode.replaceChild(newScript, oldScript);
      }
    });
  }
  function updateGtagConsent(preferences) {
    if (typeof gtag === "function") {
      gtag('consent', 'update', {
        'analytics_storage': preferences.Analytics ? 'granted' : 'denied',
        'functionality_storage': 'granted',
        'ad_storage': preferences.Marketing ? 'granted' : 'denied',
        'ad_personalization': preferences.Marketing ? 'granted' : 'denied',
        'ad_user_data': preferences.Marketing ? 'granted' : 'denied',
        'personalization_storage': preferences.Personalization ? 'granted' : 'denied',
        'security_storage': 'granted'
      });
    }
  }
  function setConsentState(preferences, cookieDays) {
    ['Analytics', 'Marketing', 'Personalization'].forEach(function(category) {
      setConsentCookie(
        'cb-consent-' + category.toLowerCase() + '_storage',
        preferences[category] ? 'true' : 'false',
        cookieDays || 365
      );
    });
    updateGtagConsent(preferences);
    const expiresAt = Date.now() + (cookieDays * 24 * 60 * 60 * 1000);
    localStorage.setItem('consentExpiresAt', expiresAt.toString());
    localStorage.setItem('consentExpirationDays', cookieDays.toString());
  }
  function getConsentPreferences() {
    return {
      Analytics: getConsentCookie('cb-consent-analytics_storage') === 'true',
      Marketing: getConsentCookie('cb-consent-marketing_storage') === 'true',
      Personalization: getConsentCookie('cb-consent-personalization_storage') === 'true'
    };
  }
  function showBanner(banner) {
    if (banner) {
      banner.style.setProperty("display", "block", "important");
      banner.style.setProperty("visibility", "visible", "important");
      banner.style.setProperty("opacity", "1", "important");
      banner.classList.add("show-banner");
      banner.classList.remove("hidden");
    }
  }
  function hideBanner(banner) {
    if (banner) {
      banner.style.setProperty("display", "none", "important");
      banner.style.setProperty("visibility", "hidden", "important");
      banner.style.setProperty("opacity", "0", "important");
      banner.classList.remove("show-banner");
      banner.classList.add("hidden");
    }
  }
async  function hideAllBanners(){
    hideBanner(document.getElementById("consent-banner"));
    hideBanner(document.getElementById("initial-consent-banner"));
    hideBanner(document.getElementById("main-banner"));
    hideBanner(document.getElementById("main-consent-banner"));
    hideBanner(document.getElementById("simple-consent-banner"));
  }
  function showAllBanners(){
    showBanner(document.getElementById("consent-banner"));
    showBanner(document.getElementById("initial-consent-banner"));
    showBanner(document.getElementById("main-banner"));
    showBanner(document.getElementById("main-consent-banner"));
    showBanner(document.getElementById("simple-consent-banner"));
  }

  // --- Encryption Helper Functions ---
  function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function uint8ArrayToBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }

  async function importHardcodedKey() {
    const keyBytes = base64ToUint8Array(ENCRYPTION_KEY);
    return crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptWithHardcodedKey(data) {
    try {
      const key = await importHardcodedKey();
      const iv = base64ToUint8Array(ENCRYPTION_IV);
      const encoder = new TextEncoder();
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(data)
      );
      return uint8ArrayToBase64(new Uint8Array(encryptedBuffer));
    } catch (error) {
      throw error;
    }
  }

  // --- Advanced: Visitor session token generation ---
  function isTokenExpired(token) {
    if (!token) return true;
    const [payloadBase64] = token.split('.');
    if (!payloadBase64) return true;
    try {
      const payload = JSON.parse(atob(payloadBase64));
      if (!payload.exp) return true;
      return payload.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  }
  async function getOrCreateVisitorId() {
    let visitorId = localStorage.getItem('visitorId');
    if (!visitorId) {
      visitorId = crypto.randomUUID();
      localStorage.setItem('visitorId', visitorId);
    }
    return visitorId;
  }
  async function cleanHostname(hostname) {
    let cleaned = hostname.replace(/^www\./, '');
    cleaned = cleaned.split('.')[0];
    return cleaned;
  }
  
  // Add session cleanup function
  function clearVisitorSession() {
    localStorage.removeItem('visitorId');
    localStorage.removeItem('visitorSessionToken');
    localStorage.removeItem('consent-given');
    localStorage.removeItem('consentExpiresAt');
    localStorage.removeItem('consentExpirationDays');
    console.log('Visitor session cleared due to server error');
  }
  
  // Add flag to prevent concurrent token requests
  let tokenRequestInProgress = false;
  
  async function getVisitorSessionToken() {
    try {
      // Prevent concurrent requests
      if (tokenRequestInProgress) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const existingToken = localStorage.getItem('visitorSessionToken');
        if (existingToken && !isTokenExpired(existingToken)) {
          return existingToken;
        }
      }
      
      const existingToken = localStorage.getItem('visitorSessionToken');
      if (existingToken && !isTokenExpired(existingToken)) {
        return existingToken;
      }
      
      // Set flag to prevent concurrent requests
      tokenRequestInProgress = true;
    
      const visitorId = await getOrCreateVisitorId();
      const siteName = await cleanHostname(window.location.hostname);
      const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          visitorId: visitorId,
          // userAgent: navigator.userAgent, // Removed to fix fingerprinting warnings
          siteName: siteName
        })
      });
      
      if (!response.ok) {
        // Handle 500 errors by clearing stale data and retrying
        if (response.status === 500) {
          console.log('Server error (500) - clearing visitor data and retrying...');
          clearVisitorSession();
          
          // Generate new visitor ID and retry once
          const newVisitorId = await getOrCreateVisitorId();
          const retryResponse = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              visitorId: newVisitorId,
              // userAgent: navigator.userAgent, // Removed to fix fingerprinting warnings
              siteName: siteName
            })
          });
          
          if (!retryResponse.ok) {
            throw new Error(`Retry failed after clearing session: ${retryResponse.status}`);
          }
          
          const retryData = await retryResponse.json();
          // Store token immediately
          localStorage.setItem('visitorSessionToken', retryData.token);
          return retryData.token;
        }
        
        throw new Error(`Failed to get visitor session token: ${response.status}`);
      }
      
      const data = await response.json();
      // Store token immediately to prevent timing issues
      localStorage.setItem('visitorSessionToken', data.token);
      return data.token;
    } catch (error) {
      console.error('Error getting visitor session token:', error);
      return null;
    } finally {
      // Always reset the flag regardless of success or failure
      tokenRequestInProgress = false;
    }
  }

  // --- Advanced: Fetch cookie expiration days from server ---
  async function fetchCookieExpirationDays() {
    const sessionToken = localStorage.getItem("visitorSessionToken");
    if (!sessionToken) return 180;
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
      if (!response.ok) return 180;
      const data = await response.json();
      if (data && data.cookieExpiration !== null && data.cookieExpiration !== undefined) {
        return parseInt(data.cookieExpiration, 10);
      }
      return 180;
    } catch {
      return 180;
    }
  }

  // --- Manual override for testing purposes ---
  function getTestLocationOverride() {
    // Check if there's a manual override in localStorage for testing
    const override = localStorage.getItem('test_location_override');
    if (override) {
      try {
        return JSON.parse(override);
      } catch {
        return null;
      }
    }
    return null;
  }

  // --- Advanced: Detect location and banner type ---
  let country = null;
  async function detectLocationAndGetBannerType() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      console.log('Location detection - Session token exists:', !!sessionToken);
      
      if (!sessionToken) {
        console.log('Location detection failed: No session token');
        return null;
      }
      
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      console.log('Location detection - Site name:', siteName);
      
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`;
      console.log('Location detection - API URL:', apiUrl);
      
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${sessionToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
      });
      
      console.log('Location detection - Response status:', response.status, response.statusText);
      
      if (!response.ok) {
        console.log('Location detection failed: Response not ok');
        return null;
      }
      
      const data = await response.json();
      console.log('Location detection - Raw response data:', data);
      
      if (!data.bannerType) {
        console.log('Location detection failed: No bannerType in response');
        return null;
      }
      
      country = data.country;
      console.log('Location detection - Success:', {
        country: data.country,
        bannerType: data.bannerType
      });
      
      return data;
    } catch (error) {
      console.log('Location detection - Error:', error);
      return null;
    }
  }

  // --- Advanced: Encrypt and save consent preferences to server ---
  async function saveConsentStateToServer(preferences, cookieDays, includeUserAgent) {
    try {
      const clientId = window.location.hostname;
      const visitorId = localStorage.getItem("visitorId");
      const policyVersion = "1.2";
      const timestamp = new Date().toISOString();
      const sessionToken = localStorage.getItem("visitorSessionToken");
      
      if (!sessionToken) {
        return;
      }

      // Prepare the complete payload first
      const fullPayload = {
        clientId,
        visitorId,
        preferences, // Raw preferences object, not encrypted individually
        policyVersion,
        timestamp,
        country: country || "IN",
        bannerType: preferences.bannerType || "GDPR",
        expiresAtTimestamp: Date.now() + ((cookieDays || 365) * 24 * 60 * 60 * 1000),
        expirationDurationDays: cookieDays || 365,
        metadata: {
          ...(includeUserAgent && { userAgent: navigator.userAgent }), // Only include userAgent if allowed
          language: navigator.language,
          platform: navigator.userAgentData?.platform || "unknown",
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
      };

      // Encrypt the entire payload as one encrypted string
      const encryptedPayload = await encryptWithHardcodedKey(JSON.stringify(fullPayload));

      // Send only the encrypted payload
      const requestBody = {
        encryptedData: encryptedPayload
      };

      const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${sessionToken}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Server error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      
    } catch (error) {
      // Silent error handling
    }
  }

  // --- Advanced: Show saved preferences in preferences panel ---
  function updatePreferenceForm(preferences) {
    const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
    const marketingCheckbox = document.querySelector('[data-consent-id="marketing-checkbox"]');
    const personalizationCheckbox = document.querySelector('[data-consent-id="personalization-checkbox"]');
    const analyticsCheckbox = document.querySelector('[data-consent-id="analytics-checkbox"]');
    if (necessaryCheckbox) {
      necessaryCheckbox.checked = true;
      necessaryCheckbox.disabled = true;
    }
    if (marketingCheckbox) {
      marketingCheckbox.checked = Boolean(preferences.Marketing);
    }
    if (personalizationCheckbox) {
      personalizationCheckbox.checked = Boolean(preferences.Personalization);
    }
    if (analyticsCheckbox) {
      analyticsCheckbox.checked = Boolean(preferences.Analytics);
    }
  }

  // --- Publishing status and removal helpers ---
  async function checkPublishingStatus() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      if (!sessionToken) {
        return false;
      }
      const siteDomain = window.location.hostname;
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/site/subscription-status?siteDomain=${encodeURIComponent(siteDomain)}`;
      const response = await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${sessionToken}`,
          "Accept": "application/json"
        }
      });
      if (!response.ok) {
        return false;
      }
      const data = await response.json();
      return data.canPublishToCustomDomain === true;
    } catch (error) {
      return false;
    }
  }
  function removeConsentElements() {
    const selectors = [
      '.consentbit-gdpr-banner-div',
      '.consentbit-preference-div',
      '.consentbit-change-preference',
      '.consentbit-ccpa-banner-div',
      '.consentbit-ccpa_preference',
    ];
    selectors.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => el.remove());
    });
  }
  function isStagingHostname() {
    const hostname = window.location.hostname;
    return hostname.includes('.webflow.io') || hostname.includes('localhost') || hostname.includes('127.0.0.1');
  }

  // --- Load Consent Styles ---
  function loadConsentStyles() {
    try {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css";
      link.type = "text/css";
      const link2 = document.createElement("link");
      link2.rel = "stylesheet";
      link2.href = "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css";
      document.head.appendChild(link2);
      link.onerror = function () {};
      link.onload = function () {};
      document.head.appendChild(link);
    } catch (error) {
      // Silent error handling
    }
  }

  // --- Main ---
  document.addEventListener('DOMContentLoaded', async function() {
 await   hideAllBanners();
    checkConsentExpiration();

    let canPublish = false;
    let isStaging = false;
    let locationData = null;
    
    // Set up toggle consent button FIRST (outside conditional blocks)
    const toggleConsentBtn = document.getElementById('toggle-consent-btn');
    
    if (toggleConsentBtn) {
      toggleConsentBtn.onclick = function(e) {
        e.preventDefault();
        
        // Find banner elements
        const consentBanner = document.getElementById("consent-banner");
        const ccpaBanner = document.getElementById("initial-consent-banner");
        const mainBanner = document.getElementById("main-banner");
        
        // Force show appropriate banner
        if (locationData && locationData.bannerType === "CCPA" && ccpaBanner) {
          hideAllBanners();
          showBanner(ccpaBanner);
          
          // Force display with additional methods if needed
          ccpaBanner.style.display = "block";
          ccpaBanner.style.visibility = "visible";
          ccpaBanner.hidden = false;
          ccpaBanner.classList.remove("hidden");
          ccpaBanner.classList.add("show-banner");
        } else if (consentBanner) {
          hideAllBanners();
          showBanner(consentBanner);
          
          // Force display with additional methods if needed
          consentBanner.style.display = "block";
          consentBanner.style.visibility = "visible";
          consentBanner.hidden = false;
          consentBanner.classList.remove("hidden");
          consentBanner.classList.add("show-banner");
        }
        
        // Update preferences if function exists
        if (typeof updatePreferenceForm === 'function') {
          updatePreferenceForm(getConsentPreferences());
        }
      };
    }
    
    try {
      const token = await getVisitorSessionToken();
      if (!token) {
        // Instead of immediate reload, try clearing session and retry once
        console.log('No token received, clearing session and retrying...');
        clearVisitorSession();
        const retryToken = await getVisitorSessionToken();
        if (!retryToken) {
          console.log('Retry failed, reloading page...');
          setTimeout(() => location.reload(), 3000);
          return;
        }
        localStorage.setItem('visitorSessionToken', retryToken);
      } else {
        // Store token immediately if not already stored
        if (!localStorage.getItem('visitorSessionToken')) {
          localStorage.setItem('visitorSessionToken', token);
        }
      }
      canPublish = await checkPublishingStatus();
      isStaging = isStagingHostname();
      
      if (!canPublish && !isStaging) {
        removeConsentElements();
        return;
      }
    } catch (error) {
      console.error('Token initialization failed:', error);
      clearVisitorSession();
      setTimeout(() => location.reload(), 3000);
      return;
    }

    // Only show banners and run consent logic if canPublish or isStaging
    if (canPublish || isStaging) {
      function qid(id) { return document.getElementById(id); }
      function qs(sel) { return document.querySelector(sel); }
      const banners = {
        consent: qid("consent-banner"),
        ccpa: qid("initial-consent-banner"),
        main: qid("main-banner")
      };
      
      console.log('Available banners:', {
        consent: !!banners.consent,
        ccpa: !!banners.ccpa,
        main: !!banners.main
      });
      
      // Detect which banner to show
      const testOverride = getTestLocationOverride();
      if (testOverride) {
        console.log('Using test location override:', testOverride);
        locationData = testOverride;
        country = testOverride.country;
      } else {
        locationData = await detectLocationAndGetBannerType();
      }
      console.log('Final location data:', locationData);
      
      const consentGiven = localStorage.getItem("consent-given");
      let cookieDays = await fetchCookieExpirationDays();
      // On load: apply preferences if already set
      const prefs = getConsentPreferences();
      updatePreferenceForm(prefs);
      
      // Only show banners if consent not given AND location data is available
      if (!consentGiven) {
        // Show banner based on location data, or default GDPR banner if no location data
        if (locationData && locationData.bannerType === "CCPA") {
          console.log('CCPA banner should show:', {
            locationData: locationData,
            bannerType: locationData.bannerType,
            ccpaBannerExists: !!banners.ccpa
          });
          // CCPA: Unblock all scripts initially (opt-out model)
          enableScriptsByCategories(['Analytics', 'Marketing', 'Personalization']);
          setConsentState({ Analytics: true, Marketing: true, Personalization: true }, cookieDays);
          showBanner(banners.ccpa);
          hideBanner(banners.consent);
          
          // Force display CCPA banner with same logic as GDPR banner
          if (banners.ccpa) {
            banners.ccpa.style.display = "block";
            banners.ccpa.style.visibility = "visible";
            banners.ccpa.hidden = false;
            banners.ccpa.classList.remove("hidden");
            banners.ccpa.classList.add("show-banner");
          }
        } else {
          // Show GDPR banner (default when no location data or when location indicates GDPR)
          console.log('GDPR banner should show:', {
            locationData: locationData,
            bannerType: locationData ? locationData.bannerType : 'default-GDPR',
            consentBannerExists: !!banners.consent,
            reason: locationData ? 'based on location data' : 'default due to no location data'
          });
          showBanner(banners.consent);
          hideBanner(banners.ccpa);
        }
      } else {
        // Consent already given - apply existing preferences
        if (prefs.Analytics || prefs.Marketing || prefs.Personalization) {
          enableScriptsByCategories(Object.keys(prefs).filter(k => prefs[k]));
          updateGtagConsent(prefs);
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
        } else {
          blockScriptsByCategory();
          updateGtagConsent(prefs);
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
        }
      }
      // Accept all
      const acceptBtn = qid('accept-btn');
      if (acceptBtn) {
        acceptBtn.onclick = async function(e) {
          e.preventDefault();
          const preferences = { Analytics: true, Marketing: true, Personalization: true, bannerType: locationData ? locationData.bannerType : undefined };
          setConsentState(preferences, cookieDays);
          // Unblock ALL scripts (no category consideration needed)
          const allScripts = document.querySelectorAll('script[type="text/plain"][data-blocked-by-consent="true"]');
          allScripts.forEach(function(oldScript) {
            var newScript = document.createElement('script');
            for (var i = 0; i < oldScript.attributes.length; i++) {
              var attr = oldScript.attributes[i];
              if (attr.name === 'type') {
                newScript.type = 'text/javascript';
              } else if (attr.name !== 'data-blocked-by-consent') {
                newScript.setAttribute(attr.name, attr.value);
              }
            }
            if (oldScript.innerHTML) {
              newScript.innerHTML = oldScript.innerHTML;
            }
            oldScript.parentNode.replaceChild(newScript, oldScript);
          });
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          hideBanner(banners.main);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, true); // Pass true to include userAgent
          updatePreferenceForm(preferences);
        };
      }
      // Reject all
      const declineBtn = qid('decline-btn');
      if (declineBtn) {
        declineBtn.onclick = async function(e) {
          e.preventDefault();
          const preferences = { Analytics: false, Marketing: false, Personalization: false, bannerType: locationData ? locationData.bannerType : undefined };
          setConsentState(preferences, cookieDays);
          // Block ALL scripts except necessary/essential
          blockScriptsByCategory();
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          hideBanner(banners.main);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, false); // Pass false to exclude userAgent
          updatePreferenceForm(preferences);
        };
      }
      // Do Not Share (CCPA)
      const doNotShareBtn = qid('do-not-share-link');
      console.log('Looking for do-not-share-link button:', !!doNotShareBtn);
      if (doNotShareBtn) {
        console.log('Do-not-share-link button found, attaching event listener');
        doNotShareBtn.onclick = function(e) {
          e.preventDefault();
          console.log('Do Not Share clicked!');
          
          // Hide initial CCPA banner with FORCE
          const initialBanner = document.getElementById('initial-consent-banner');
          if (initialBanner) {
            console.log('Hiding initial CCPA banner with force...');
            console.log('Initial banner BEFORE hiding - display:', window.getComputedStyle(initialBanner).display);
            console.log('Initial banner BEFORE hiding - visibility:', window.getComputedStyle(initialBanner).visibility);
            console.log('Initial banner BEFORE hiding - opacity:', window.getComputedStyle(initialBanner).opacity);
            
            hideBanner(initialBanner);
            
            // Check if it actually got hidden
            setTimeout(() => {
              console.log('Initial banner AFTER hiding - display:', window.getComputedStyle(initialBanner).display);
              console.log('Initial banner AFTER hiding - visibility:', window.getComputedStyle(initialBanner).visibility);
              console.log('Initial banner AFTER hiding - opacity:', window.getComputedStyle(initialBanner).opacity);
            }, 10);
            
            console.log('Initial CCPA banner forcefully hidden');
          } else {
            console.log('Initial CCPA banner not found');
          }
          
          // Show main consent banner with force
          const mainBanner = document.getElementById('main-consent-banner');
          if (mainBanner) {
            console.log('Main consent banner found, forcing visibility...');
            console.log('Main banner BEFORE showing - display:', window.getComputedStyle(mainBanner).display);
            console.log('Main banner BEFORE showing - visibility:', window.getComputedStyle(mainBanner).visibility);
            console.log('Main banner BEFORE showing - opacity:', window.getComputedStyle(mainBanner).opacity);
            console.log('Main banner BEFORE showing - classes:', mainBanner.className);
            
            showBanner(mainBanner);
            
            // Check if it actually became visible
            setTimeout(() => {
              console.log('Main banner AFTER showing - display:', window.getComputedStyle(mainBanner).display);
              console.log('Main banner AFTER showing - visibility:', window.getComputedStyle(mainBanner).visibility);
              console.log('Main banner AFTER showing - opacity:', window.getComputedStyle(mainBanner).opacity);
              console.log('Main banner AFTER showing - classes:', mainBanner.className);
              console.log('Main banner AFTER showing - offsetParent:', !!mainBanner.offsetParent);
              
              // If still not visible, let's see what CSS rules are applied
              if (window.getComputedStyle(mainBanner).display === 'none') {
                console.error('CCPA Main banner STILL HIDDEN after showBanner! CSS might be overriding it.');
                console.log('All CSS rules on main banner:');
                const styles = window.getComputedStyle(mainBanner);
                console.log('Computed display:', styles.display);
                console.log('Computed visibility:', styles.visibility);
                console.log('Computed opacity:', styles.opacity);
                console.log('Computed position:', styles.position);
                console.log('Computed z-index:', styles.zIndex);
              } else {
                console.log('✅ CCPA Main banner is now visible!');
              }
            }, 10);
            
            console.log('Main consent banner forced visible');
          } else {
            console.error('main-consent-banner NOT FOUND!');
            // Debug: show all available consent elements
            console.log('Available consent elements:');
            document.querySelectorAll('[id*="consent"], [class*="consent"]').forEach((el, i) => {
              console.log(`${i + 1}. ${el.tagName} - ID: ${el.id || 'none'} - Classes: ${el.className || 'none'}`);
            });
          }
          
          console.log('Do Not Share handler completed');
        };
      } else {
        console.error('Do-not-share-link button NOT FOUND!');
        // Try alternative selectors
        const alternativeBtn = document.querySelector('.do-not-share-link') ||
                              document.querySelector('[data-action="do-not-share"]') ||
                              document.querySelector('a[href*="do-not-share"]');
        if (alternativeBtn) {
          console.log('Found alternative do-not-share button:', alternativeBtn);
        } else {
          console.error('No do-not-share button found with any selector');
        }
      }
      
      // CCPA Preference Accept button
      const ccpaPreferenceAcceptBtn = document.getElementById('consebit-ccpa-prefrence-accept');
      if (ccpaPreferenceAcceptBtn) {
        ccpaPreferenceAcceptBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Read CCPA preference checkbox values
          const ccpaToggleCheckboxes = document.querySelectorAll('.consentbit-ccpa-prefrence-toggle input[type="checkbox"]');
          let preferences = { Analytics: true, Marketing: true, Personalization: true }; // Default to true (unblocked)
          
          // If checkboxes are checked, it means "Do Not Share" for that category (block scripts)
          ccpaToggleCheckboxes.forEach(checkbox => {
            if (checkbox.checked) {
              // Checkbox checked means DO NOT SHARE (block/false)
              const checkboxName = checkbox.name || checkbox.getAttribute('data-category') || '';
              if (checkboxName.toLowerCase().includes('analytics')) {
                preferences.Analytics = false;
              } else if (checkboxName.toLowerCase().includes('marketing') || checkboxName.toLowerCase().includes('advertising')) {
                preferences.Marketing = false;
              } else if (checkboxName.toLowerCase().includes('personalization') || checkboxName.toLowerCase().includes('functional')) {
                preferences.Personalization = false;
              }
            }
          });
          
          // Add banner type
          preferences.bannerType = locationData ? locationData.bannerType : undefined;
          preferences.donotshare = false; // CCPA Accept means do not share = false
          
          // Save consent state
          setConsentState(preferences, cookieDays);
          
          // Block/enable scripts based on preferences (original CCPA logic)
          if (preferences.Analytics || preferences.Marketing || preferences.Personalization) {
            enableScriptsByCategories(Object.keys(preferences).filter(k => preferences[k]));
          } else {
            blockScriptsByCategory();
          }
          
          // Hide both CCPA banners using hideBanner function
          hideBanner(banners.ccpa);
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          
          // Set consent as given
          localStorage.setItem("consent-given", "true");
          
          // Save to server (original CCPA logic - always include userAgent)
          await saveConsentStateToServer(preferences, cookieDays, true);
          updatePreferenceForm(preferences);
        };
      }
      
      // CCPA Preference Decline button
      const ccpaPreferenceDeclineBtn = document.getElementById('consebit-ccpa-prefrence-decline');
      if (ccpaPreferenceDeclineBtn) {
        ccpaPreferenceDeclineBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Decline means block all scripts (all false)
          const preferences = { 
            Analytics: false, 
            Marketing: false, 
            Personalization: false, 
            donotshare: true, // CCPA Decline means do not share = true
            bannerType: locationData ? locationData.bannerType : undefined 
          };
          
          // Save consent state
          setConsentState(preferences, cookieDays);
          
          // Block all scripts (original CCPA logic)
          blockScriptsByCategory();
          
          // Hide both CCPA banners using hideBanner function
          hideBanner(banners.ccpa);
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          
          // Set consent as given
          localStorage.setItem("consent-given", "true");
          
          // Save to server (original CCPA logic - always include userAgent)
          await saveConsentStateToServer(preferences, cookieDays, true);
          updatePreferenceForm(preferences);
        };
      }
      
      // Save button (CCPA)
      const saveBtn = qid('save-btn');
      if (saveBtn) {
        saveBtn.onclick = async function(e) {
          e.preventDefault();
          
          // Read the do-not-share checkbox value
          const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
          let preferences;
          let includeUserAgent;
          
          if (doNotShareCheckbox && doNotShareCheckbox.checked) {
            // Checkbox checked means "Do Not Share" - block all scripts and restrict userAgent
            preferences = { 
              Analytics: false, 
              Marketing: false, 
              Personalization: false,
              donotshare: true,
              bannerType: locationData ? locationData.bannerType : undefined 
            };
            includeUserAgent = false; // Restrict userAgent
          } else {
            // Checkbox unchecked means "Allow" - unblock all scripts and allow userAgent
            preferences = { 
              Analytics: true, 
              Marketing: true, 
              Personalization: true,
              donotshare: false,
              bannerType: locationData ? locationData.bannerType : undefined 
            };
            includeUserAgent = true; // Allow userAgent
          }
          
          // Save consent state
          setConsentState(preferences, cookieDays);
          
          // Handle script blocking/unblocking based on checkbox state
          if (doNotShareCheckbox && doNotShareCheckbox.checked) {
            // Block all scripts except necessary/essential
            blockScriptsByCategory();
          } else {
            // Unblock ALL scripts (no category consideration)
            const allScripts = document.querySelectorAll('script[type="text/plain"][data-blocked-by-consent="true"]');
            allScripts.forEach(function(oldScript) {
              var newScript = document.createElement('script');
              for (var i = 0; i < oldScript.attributes.length; i++) {
                var attr = oldScript.attributes[i];
                if (attr.name === 'type') {
                  newScript.type = 'text/javascript';
                } else if (attr.name !== 'data-blocked-by-consent') {
                  newScript.setAttribute(attr.name, attr.value);
                }
              }
              if (oldScript.innerHTML) {
                newScript.innerHTML = oldScript.innerHTML;
              }
              oldScript.parentNode.replaceChild(newScript, oldScript);
            });
          }
          
          // Hide both CCPA banners
          hideBanner(banners.ccpa);
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          const mainConsentBanner = document.getElementById('main-consent-banner');
          hideBanner(mainConsentBanner);
          
          // Set consent as given
          localStorage.setItem("consent-given", "true");
          
          // Save to server with appropriate userAgent setting based on checkbox
          await saveConsentStateToServer(preferences, cookieDays, includeUserAgent);
          updatePreferenceForm(preferences);
        };
      }
      
      // Preferences button (show preferences panel)
      const preferencesBtn = qid('preferences-btn');
      if (preferencesBtn) {
        preferencesBtn.onclick = function(e) {
          e.preventDefault();
          hideBanner(banners.consent);
          showBanner(banners.main);
          updatePreferenceForm(getConsentPreferences());
        };
      }
      // Save Preferences button
      const savePreferencesBtn = qid('save-preferences-btn');
      if (savePreferencesBtn) {
        savePreferencesBtn.onclick = async function(e) {
          e.preventDefault();
          // Read checkboxes
          const analytics = !!qs('[data-consent-id="analytics-checkbox"]:checked');
          const marketing = !!qs('[data-consent-id="marketing-checkbox"]:checked');
          const personalization = !!qs('[data-consent-id="personalization-checkbox"]:checked');
          const preferences = {
            Analytics: analytics,
            Marketing: marketing,
            Personalization: personalization,
            bannerType: locationData ? locationData.bannerType : undefined
          };
          setConsentState(preferences, cookieDays);
          // First block ALL scripts except necessary/essential
          blockScriptsByCategory();
          // Then enable only scripts for selected categories
          const selectedCategories = Object.keys(preferences).filter(k => preferences[k] && k !== 'bannerType');
          if (selectedCategories.length > 0) {
            enableScriptsByCategories(selectedCategories);
          }
          hideBanner(banners.main);
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, true); // Include userAgent for preferences
          updatePreferenceForm(preferences);
        };
      }
      // Cancel button (go back to main banner)
      const cancelBtn = qid('cancel-btn');
      console.log('Looking for cancel button with ID "cancel-btn":', !!cancelBtn);
      if (cancelBtn) {
        console.log('Cancel button found and event listener being attached');
        cancelBtn.onclick = async function(e) {
          e.preventDefault();
          
          console.log('CANCEL BUTTON CLICKED - Starting script blocking and consent saving...');
          
          // STEP 1: Block all scripts except necessary/essential
          console.log('Step 1: Blocking scripts...');
          blockScriptsByCategory();
          
          // STEP 2: Also block any scripts that are already running by disabling them
          console.log('Step 2: Disabling active tracking scripts...');
          // Disable Google Analytics if present
          if (typeof gtag !== 'undefined') {
            gtag('consent', 'update', {
              'analytics_storage': 'denied',
              'ad_storage': 'denied',
              'ad_personalization': 'denied',
              'ad_user_data': 'denied',
              'personalization_storage': 'denied'
            });
            console.log('Google Analytics consent set to denied');
          }
          
          // Disable Google Tag Manager if present
          if (typeof window.dataLayer !== 'undefined') {
            window.dataLayer.push({
              'event': 'consent_denied',
              'analytics_storage': 'denied',
              'ad_storage': 'denied'
            });
            console.log('Google Tag Manager consent denied event pushed');
          }
          
          // STEP 3: Uncheck all preference checkboxes
          console.log('Step 3: Unchecking all checkboxes...');
          const analyticsCheckbox = qs('[data-consent-id="analytics-checkbox"]');
          const marketingCheckbox = qs('[data-consent-id="marketing-checkbox"]');
          const personalizationCheckbox = qs('[data-consent-id="personalization-checkbox"]');
          
          if (analyticsCheckbox) {
            analyticsCheckbox.checked = false;
            console.log('Analytics checkbox unchecked');
          }
          if (marketingCheckbox) {
            marketingCheckbox.checked = false;
            console.log('Marketing checkbox unchecked');
          }
          if (personalizationCheckbox) {
            personalizationCheckbox.checked = false;
            console.log('Personalization checkbox unchecked');
          }
          
          // STEP 4: Save consent state with all preferences as false (like decline behavior)
          console.log('Step 4: Saving consent state...');
          const preferences = { 
            Analytics: false, 
            Marketing: false, 
            Personalization: false, 
            bannerType: locationData ? locationData.bannerType : undefined 
          };
          
          console.log('Preferences to save:', preferences);
          
          setConsentState(preferences, cookieDays);
          updateGtagConsent(preferences);
          
          // STEP 5: Set consent as given and save to server
          console.log('Step 5: Marking consent as given and saving to server...');
          localStorage.setItem("consent-given", "true");
          console.log('Consent marked as given in localStorage');
          
          try {
            await saveConsentStateToServer(preferences, cookieDays, false); // Exclude userAgent like decline
            console.log('Consent successfully saved to server');
          } catch (error) {
            console.error('Failed to save consent to server:', error);
          }
          
          // STEP 6: Hide banners
          console.log('Step 6: Hiding banners...');
          hideBanner(banners.main);
          hideBanner(banners.consent);
          
          console.log('CANCEL BUTTON COMPLETED - All scripts blocked, consent saved as declined');
          
          // Verify the state was saved correctly
          setTimeout(() => {
            const savedPrefs = getConsentPreferences();
            console.log('Verification - Saved preferences:', savedPrefs);
            console.log('Verification - Consent given status:', localStorage.getItem("consent-given"));
          }, 100);
        };
      } else {
        console.error('Cancel button with ID "cancel-btn" NOT FOUND! Please check HTML structure.');
        // Try alternative selectors as fallback
        const alternativeCancel = document.querySelector('.cancel-btn') || 
                                 document.querySelector('[data-action="cancel"]') ||
                                 document.querySelector('button[name="cancel"]');
        if (alternativeCancel) {
          console.log('Found alternative cancel button:', alternativeCancel);
        } else {
          console.error('No cancel button found with any common selector');
        }
      }
      // CCPA Link Block - Show CCPA Banner
      const ccpaLinkBlock = document.getElementById('consentbit-ccpa-linkblock');
      if (ccpaLinkBlock) {
        ccpaLinkBlock.onclick = function(e) {
          e.preventDefault();
          
          // Show CCPA banner using showBanner function
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          showBanner(ccpaBannerDiv);
          
          // Also show the CCPA banner if it exists
          showBanner(banners.ccpa);
        };
      }
      
      // Close Consent Banner functionality (CCPA only)
      const closeConsentBanner = document.getElementById('close-consent-banner');
      const initialConsentBanner = document.getElementById('initial-consent-banner');
      
      // Only apply close banner logic for CCPA banners
      if (closeConsentBanner && initialConsentBanner && locationData && locationData.bannerType === "CCPA") {
        // Check if close-consent-banner is visible
        const isCloseConsentVisible = closeConsentBanner.style.display !== 'none' && 
                                    !closeConsentBanner.classList.contains('hidden') &&
                                    closeConsentBanner.offsetParent !== null;
        
        if (isCloseConsentVisible) {
          hideBanner(initialConsentBanner);
        }
        
        // Handle close-consent-banner click
        closeConsentBanner.onclick = function(e) {
          e.preventDefault();
          
          // Hide close-consent-banner and show initial-consent-banner
          hideBanner(closeConsentBanner);
          showBanner(initialConsentBanner);
          
          // Force display initial consent banner
          initialConsentBanner.style.display = "block";
          initialConsentBanner.style.visibility = "visible";
          initialConsentBanner.hidden = false;
          initialConsentBanner.classList.remove("hidden");
          initialConsentBanner.classList.add("show-banner");
        };
      }
      
      // Load consent styles after banners are shown
      loadConsentStyles();
    }
  });

  function checkConsentExpiration() {
    const expiresAt = localStorage.getItem('consentExpiresAt');
    if (expiresAt && Date.now() > parseInt(expiresAt, 10)) {
      // Consent expired: clear consent state
      localStorage.removeItem('consent-given');
      localStorage.removeItem('consent-preferences');
      localStorage.removeItem('consentExpiresAt');
      localStorage.removeItem('consentExpirationDays');
      // Optionally, clear consent cookies as well
      ['analytics', 'marketing', 'personalization'].forEach(category => {
        setConsentCookie('cb-consent-' + category + '_storage', '', -1);
      });
    }
  }
})(); 

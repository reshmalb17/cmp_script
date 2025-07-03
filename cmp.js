
(function () {
  
  const ENCRYPTION_KEY = "t95w6oAeL1hrerrvvvKok/3GFNwxzfLxiWTETfZurpI="; 
  const ENCRYPTION_IV = "yVSYDuWajEid8kDz"; 

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
        var categories = category.split(',').map(function(cat) { return cat.trim(); });
        
        var hasEssentialCategory = categories.some(function(cat) { 
          var lowercaseCat = cat.toLowerCase();
          return lowercaseCat === 'necessary' || lowercaseCat === 'essential'; 
        });
        
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
    
    if (preferences.hasOwnProperty('donotshare')) {
      setConsentCookie(
        'cb-consent-donotshare',
        preferences.donotshare ? 'true' : 'false',
        cookieDays || 365
      );
    }
    
    updateGtagConsent(preferences);
    const expiresAt = Date.now() + (cookieDays * 24 * 60 * 60 * 1000);
    localStorage.setItem('consentExpiresAt', expiresAt.toString());
    localStorage.setItem('consentExpirationDays', cookieDays.toString());
  }
  function getConsentPreferences() {
    return {
      Analytics: getConsentCookie('cb-consent-analytics_storage') === 'true',
      Marketing: getConsentCookie('cb-consent-marketing_storage') === 'true',
      Personalization: getConsentCookie('cb-consent-personalization_storage') === 'true',
      donotshare: getConsentCookie('cb-consent-donotshare') === 'true'
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
  

  function clearVisitorSession() {
    localStorage.removeItem('visitorId');
    localStorage.removeItem('visitorSessionToken');
    localStorage.removeItem('consent-given');
    localStorage.removeItem('consentExpiresAt');
    localStorage.removeItem('consentExpirationDays');
  }
  
  
  let tokenRequestInProgress = false;
  
  async function getVisitorSessionToken() {
    try {
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
          
          siteName: siteName
        })
      });
      
      if (!response.ok) {
        if (response.status === 500) {
          clearVisitorSession();
          
          const newVisitorId = await getOrCreateVisitorId();
          const retryResponse = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              visitorId: newVisitorId,
              siteName: siteName
            })
          });
          
          if (!retryResponse.ok) {
            throw new Error(`Retry failed after clearing session: ${retryResponse.status}`);
          }
          
          const retryData = await retryResponse.json();
          localStorage.setItem('visitorSessionToken', retryData.token);
          return retryData.token;
        }
        
        throw new Error(`Failed to get visitor session token: ${response.status}`);
      }
      
      const data = await response.json();
      localStorage.setItem('visitorSessionToken', data.token);
      return data.token;
    } catch (error) {
      return null;
    } finally {
      tokenRequestInProgress = false;
    }
  }

 
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

 
  function getTestLocationOverride() {
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


  let country = null;
  async function detectLocationAndGetBannerType() {
    try {
      const sessionToken = localStorage.getItem('visitorSessionToken');
      
      if (!sessionToken) {
        return null;
      }
      
      const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];
      
      const apiUrl = `https://cb-server.web-8fb.workers.dev/api/cmp/detect-location?siteName=${encodeURIComponent(siteName)}`;
      
      const response = await fetch(apiUrl, {
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
      
      if (!data.bannerType) {
        return null;
      }
      
      country = data.country;
      
      return data;
    } catch (error) {
      return null;
    }
  }

 
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

      const fullPayload = {
        clientId,
        visitorId,
        preferences, // Raw preferences object, not encrypted individually
        policyVersion,
        timestamp,
        country: country ,
        bannerType: preferences.bannerType || "GDPR",
        expiresAtTimestamp: Date.now() + ((cookieDays || 365) * 24 * 60 * 60 * 1000),
        expirationDurationDays: cookieDays || 365,
        metadata: {
          ...(includeUserAgent && { userAgent: navigator.userAgent }), 
          language: navigator.language,
          platform: navigator.userAgentData?.platform || "unknown",
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        }
      };

      const encryptedPayload = await encryptWithHardcodedKey(JSON.stringify(fullPayload));

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
    }
  }

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

 
  function updateCCPAPreferenceForm(preferences) {
    const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
    if (doNotShareCheckbox) {
      if (preferences.hasOwnProperty('donotshare')) {
        doNotShareCheckbox.checked = preferences.donotshare;
      } else {
        const shouldCheck = !preferences.Analytics || !preferences.Marketing || !preferences.Personalization;
        doNotShareCheckbox.checked = shouldCheck;
      }
    }
    
    const ccpaToggleCheckboxes = document.querySelectorAll('.consentbit-ccpa-prefrence-toggle input[type="checkbox"]');
    ccpaToggleCheckboxes.forEach(checkbox => {
      const checkboxName = checkbox.name || checkbox.getAttribute('data-category') || '';
      if (checkboxName.toLowerCase().includes('analytics')) {
        checkbox.checked = !Boolean(preferences.Analytics);
      } else if (checkboxName.toLowerCase().includes('marketing') || checkboxName.toLowerCase().includes('advertising')) {
        checkbox.checked = !Boolean(preferences.Marketing);
      } else if (checkboxName.toLowerCase().includes('personalization') || checkboxName.toLowerCase().includes('functional')) {
        checkbox.checked = !Boolean(preferences.Personalization);
      }
    });
  }


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

  document.addEventListener('DOMContentLoaded', async function() {
 await   hideAllBanners();
  await  checkConsentExpiration();
  await  disableScrollOnSite();

    let canPublish = false;
    let isStaging = false;
    let locationData = null;
    
    const toggleConsentBtn = document.getElementById('toggle-consent-btn');
    
    if (toggleConsentBtn) {
      toggleConsentBtn.onclick = function(e) {
        e.preventDefault();
        
        const consentBanner = document.getElementById("consent-banner");
        const ccpaBanner = document.getElementById("initial-consent-banner");
        const mainBanner = document.getElementById("main-banner");
        
        if (locationData && locationData.bannerType === "CCPA" && ccpaBanner) {
          hideAllBanners();
          showBanner(ccpaBanner);
          
          ccpaBanner.style.display = "block";
          ccpaBanner.style.visibility = "visible";
          ccpaBanner.hidden = false;
          ccpaBanner.classList.remove("hidden");
          ccpaBanner.classList.add("show-banner");
          
          updateCCPAPreferenceForm(getConsentPreferences());
        } else if (consentBanner) {
          hideAllBanners();
          showBanner(consentBanner);
          
          consentBanner.style.display = "block";
          consentBanner.style.visibility = "visible";
          consentBanner.hidden = false;
          consentBanner.classList.remove("hidden");
          consentBanner.classList.add("show-banner");
        }
        
        if (typeof updatePreferenceForm === 'function') {
          updatePreferenceForm(getConsentPreferences());
        }
      };
    }
    
    try {
      const token = await getVisitorSessionToken();
      if (!token) {
        clearVisitorSession();
        const retryToken = await getVisitorSessionToken();
        if (!retryToken) {
          setTimeout(() => location.reload(), 3000);
          return;
        }
        localStorage.setItem('visitorSessionToken', retryToken);
      } else {
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
      clearVisitorSession();
      setTimeout(() => location.reload(), 3000);
      return;
    }

    if (canPublish || isStaging) {
      function qid(id) { return document.getElementById(id); }
      function qs(sel) { return document.querySelector(sel); }
      const banners = {
        consent: qid("consent-banner"),
        ccpa: qid("initial-consent-banner"),
        main: qid("main-banner")
      };
      
      const testOverride = getTestLocationOverride();
      if (testOverride) {
        locationData = testOverride;
        country = testOverride.country;
      } else {
        locationData = await detectLocationAndGetBannerType();
      }
      
      const consentGiven = localStorage.getItem("consent-given");
      let cookieDays = await fetchCookieExpirationDays();
      const prefs = getConsentPreferences();
      updatePreferenceForm(prefs);
      
      if (!consentGiven) {
        if (locationData && locationData.bannerType === "CCPA") {
          unblockScriptsWithDataCategory();
          showBanner(banners.ccpa);
          hideBanner(banners.consent);
          
          if (banners.ccpa) {
            banners.ccpa.style.display = "block";
            banners.ccpa.style.visibility = "visible";
            banners.ccpa.hidden = false;
            banners.ccpa.classList.remove("hidden");
            banners.ccpa.classList.add("show-banner");
          }
        } else {
          showBanner(banners.consent);
          hideBanner(banners.ccpa);
        }
      } else {
        if (locationData && locationData.bannerType === "CCPA") {
          if (prefs.Analytics || prefs.Marketing || prefs.Personalization) {
            unblockScriptsWithDataCategory();
          } else {
            blockScriptsWithDataCategory();
          }
        } else {
          if (prefs.Analytics || prefs.Marketing || prefs.Personalization) {
            enableScriptsByCategories(Object.keys(prefs).filter(k => prefs[k]));
          } else {
            blockScriptsByCategory();
          }
        }
        updateGtagConsent(prefs);
        hideBanner(banners.consent);
        hideBanner(banners.ccpa);
      }
      const acceptBtn = qid('accept-btn');
      if (acceptBtn) {
        acceptBtn.onclick = async function(e) {
          e.preventDefault();
          const preferences = { Analytics: true, Marketing: true, Personalization: true, donotshare: false, bannerType: locationData ? locationData.bannerType : undefined };
          setConsentState(preferences, cookieDays);
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
      const declineBtn = qid('decline-btn');
      if (declineBtn) {
        declineBtn.onclick = async function(e) {
          e.preventDefault();
          const preferences = { Analytics: false, Marketing: false, Personalization: false, donotshare: true, bannerType: locationData ? locationData.bannerType : undefined };
          setConsentState(preferences, cookieDays);
          blockScriptsByCategory();
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          hideBanner(banners.main);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, false); // Pass false to exclude userAgent
          updatePreferenceForm(preferences);
        };
      }
      const doNotShareBtn = qid('do-not-share-link');
      if (doNotShareBtn) {
        doNotShareBtn.onclick = function(e) {
          e.preventDefault();
          
          const initialBanner = document.getElementById('initial-consent-banner');
          if (initialBanner) {
            hideBanner(initialBanner);
          }
          
          const mainBanner = document.getElementById('main-consent-banner');
          if (mainBanner) {
            showBanner(mainBanner);
            
            updateCCPAPreferenceForm(getConsentPreferences());
          }
        };
      }
      
      const ccpaPreferenceAcceptBtn = document.getElementById('consebit-ccpa-prefrence-accept');
      if (ccpaPreferenceAcceptBtn) {
        ccpaPreferenceAcceptBtn.onclick = async function(e) {
          e.preventDefault();
          
          const ccpaToggleCheckboxes = document.querySelectorAll('.consentbit-ccpa-prefrence-toggle input[type="checkbox"]');
          let preferences = { Analytics: true, Marketing: true, Personalization: true, donotshare: false };
          
          ccpaToggleCheckboxes.forEach(checkbox => {
            if (checkbox.checked) {
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
          
          preferences.bannerType = locationData ? locationData.bannerType : undefined;
          preferences.donotshare = false; 
          
          setConsentState(preferences, cookieDays);
          
          if (preferences.Analytics || preferences.Marketing || preferences.Personalization) {
            enableScriptsByCategories(Object.keys(preferences).filter(k => preferences[k]));
          } else {
            blockScriptsByCategory();
          }
          
          hideBanner(banners.ccpa);
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          
          localStorage.setItem("consent-given", "true");
          
          await saveConsentStateToServer(preferences, cookieDays, true);
          updatePreferenceForm(preferences);
        };
      }
      
      const ccpaPreferenceDeclineBtn = document.getElementById('consebit-ccpa-prefrence-decline');
      if (ccpaPreferenceDeclineBtn) {
        ccpaPreferenceDeclineBtn.onclick = async function(e) {
          e.preventDefault();
          
          const preferences = { 
            Analytics: false, 
            Marketing: false, 
            Personalization: false, 
            donotshare: true, 
            bannerType: locationData ? locationData.bannerType : undefined 
          };
          
          setConsentState(preferences, cookieDays);
          
          blockScriptsByCategory();
          
          hideBanner(banners.ccpa);
          const ccpaPreferencePanel = document.querySelector('.consentbit-ccpa_preference');
          hideBanner(ccpaPreferencePanel);
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          hideBanner(ccpaBannerDiv);
          
          localStorage.setItem("consent-given", "true");
          
          await saveConsentStateToServer(preferences, cookieDays, true);
          updatePreferenceForm(preferences);
        };
      }
      
      const saveBtn = qid('save-btn');
      if (saveBtn) {
        saveBtn.onclick = async function(e) {
          e.preventDefault();
          
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
            includeUserAgent = false; 
          } else {
            preferences = { 
              Analytics: true, 
              Marketing: true, 
              Personalization: true,
              donotshare: false,
              bannerType: locationData ? locationData.bannerType : undefined 
            };
            includeUserAgent = true; 
          }
          
         
          setConsentState(preferences, cookieDays);
          
       
          if (doNotShareCheckbox && doNotShareCheckbox.checked) {
          
            blockScriptsWithDataCategory();
          } else {
           
            unblockScriptsWithDataCategory();
          }
          
          const mainConsentBanner = document.getElementById('main-consent-banner');
          const initialConsentBanner = document.getElementById('initial-consent-banner');
          
          if (mainConsentBanner) {
            hideBanner(mainConsentBanner);
          }
          if (initialConsentBanner) {
            hideBanner(initialConsentBanner);
          }
          
          localStorage.setItem("consent-given", "true");
          
          await saveConsentStateToServer(preferences, cookieDays, includeUserAgent);
          updatePreferenceForm(preferences);
        };
      }
      
      const preferencesBtn = qid('preferences-btn');
      if (preferencesBtn) {
        preferencesBtn.onclick = function(e) {
          e.preventDefault();
          hideBanner(banners.consent);
          showBanner(banners.main);
          updatePreferenceForm(getConsentPreferences());
        };
      }
      const savePreferencesBtn = qid('save-preferences-btn');
      if (savePreferencesBtn) {
        savePreferencesBtn.onclick = async function(e) {
          e.preventDefault();
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
          blockScriptsByCategory();
          const selectedCategories = Object.keys(preferences).filter(k => preferences[k] && k !== 'bannerType');
          if (selectedCategories.length > 0) {
            enableScriptsByCategories(selectedCategories);
          }
          hideBanner(banners.main);
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays, true); 
          updatePreferenceForm(preferences);
        };
      }


   const cancelGDPRBtn = qid('cancel-btn');
   if (cancelGDPRBtn) {
    cancelGDPRBtn.onclick = async function(e) {
       e.preventDefault();
       
       
       blockScriptsByCategory();
       
    
       if (typeof gtag !== 'undefined') {
         gtag('consent', 'update', {
           'analytics_storage': 'denied',
           'ad_storage': 'denied',
           'ad_personalization': 'denied',
           'ad_user_data': 'denied',
           'personalization_storage': 'denied'
         });
       }
       
       if (typeof window.dataLayer !== 'undefined') {
         window.dataLayer.push({
           'event': 'consent_denied',
           'analytics_storage': 'denied',
           'ad_storage': 'denied'
         });
       }
       
       const analyticsCheckbox = qs('[data-consent-id="analytics-checkbox"]');
       const marketingCheckbox = qs('[data-consent-id="marketing-checkbox"]');
       const personalizationCheckbox = qs('[data-consent-id="personalization-checkbox"]');
       
       if (analyticsCheckbox) {
         analyticsCheckbox.checked = false;
       }
       if (marketingCheckbox) {
         marketingCheckbox.checked = false;
       }
       if (personalizationCheckbox) {
         personalizationCheckbox.checked = false;
       }
       
       const preferences = { 
         Analytics: false, 
         Marketing: false, 
         Personalization: false, 
         bannerType: locationData ? locationData.bannerType : undefined 
       };
       
       setConsentState(preferences, cookieDays);
       updateGtagConsent(preferences);
       
       localStorage.setItem("consent-given", "true");
       
       try {
         await saveConsentStateToServer(preferences, cookieDays, false); // Exclude userAgent like decline
       } catch (error) {
       }
       hideBanner(banners.main);
       hideBanner(banners.consent);
     };
   }


      const cancelBtn = qid('close-consent-banner');
      if (cancelBtn) {
        cancelBtn.onclick = async function(e) {
          e.preventDefault();
          
          const mainConsentBanner = document.getElementById('main-consent-banner');
          if (mainConsentBanner) {
            hideBanner(mainConsentBanner);
          }
          
          const initialConsentBanner = document.getElementById('initial-consent-banner');
          if (initialConsentBanner) {
            showBanner(initialConsentBanner);
          }
        };
      }
      const ccpaLinkBlock = document.getElementById('consentbit-ccpa-linkblock');
      if (ccpaLinkBlock) {
        ccpaLinkBlock.onclick = function(e) {
          e.preventDefault();
          
          const ccpaBannerDiv = document.querySelector('.consentbit-ccpa-banner-div');
          showBanner(ccpaBannerDiv);
          
          showBanner(banners.ccpa);
        };
      }
      
    
      
      loadConsentStyles();
    }
  });

 async function checkConsentExpiration() {
    const expiresAt = localStorage.getItem('consentExpiresAt');
    if (expiresAt && Date.now() > parseInt(expiresAt, 10)) {
      localStorage.removeItem('consent-given');
      localStorage.removeItem('consent-preferences');
      localStorage.removeItem('consentExpiresAt');
      localStorage.removeItem('consentExpirationDays');
      ['analytics', 'marketing', 'personalization'].forEach(category => {
        setConsentCookie('cb-consent-' + category + '_storage', '', -1);
      });
    }
  }


  function unblockScriptsWithDataCategory() {
    var scripts = document.querySelectorAll('script[type="text/plain"][data-category]');
    scripts.forEach(function(oldScript) {
      var newScript = document.createElement('script');
      for (var i = 0; i < oldScript.attributes.length; i++) {
        var attr = oldScript.attributes[i];
        if (attr.name === 'type') {
          newScript.type = 'text/javascript';
        } else if (attr.name !== 'data-blocked-by-ccpa') {
          newScript.setAttribute(attr.name, attr.value);
        }
      }
      if (oldScript.innerHTML) {
        newScript.innerHTML = oldScript.innerHTML;
      }
      oldScript.parentNode.replaceChild(newScript, oldScript);
    });
  }
  
async function disableScrollOnSite(){
  const scrollControl = document.querySelector('[scroll-control="true"]');
    function toggleScrolling() {
      const banner = document.querySelector('[data-cookie-banner="true"]');
      if (!banner) return;
      const observer = new MutationObserver(() => {
        const isVisible = window.getComputedStyle(banner).display !== "none";
        document.body.style.overflow = isVisible ? "hidden" : "";
      });
      // Initial check on load
      const isVisible = window.getComputedStyle(banner).display !== "none";
      document.body.style.overflow = isVisible ? "hidden" : "";
      observer.observe(banner, { attributes: true, attributeFilter: ["style", "class"] });
    }
    if (scrollControl) {
      toggleScrolling();
    }
  

}
   
  function blockScriptsWithDataCategory() {
    var scripts = document.querySelectorAll('script[data-category]');
    scripts.forEach(function(script) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-ccpa', 'true');
      }
    });
  }
})(); 

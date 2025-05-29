(function () {
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
      if (category && category.toLowerCase() !== 'necessary' && script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-consent', 'true');
      }
    });
  }
  function enableScriptsByCategories(allowedCategories) {
    var scripts = document.querySelectorAll('script[type="text/plain"][data-category]');
    scripts.forEach(function(oldScript) {
      var category = oldScript.getAttribute('data-category');
      if (allowedCategories.includes(category)) {
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
  function hideAllBanners(){
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
async function getVisitorSessionToken() {
  try {
    const existingToken = localStorage.getItem('visitorSessionToken');
    if (existingToken && !isTokenExpired(existingToken)) {
      return existingToken;
    }

    // --- Restrict API calls to max 5 ---
    let callCount = parseInt(localStorage.getItem('visitorTokenApiCallCount') || '0', 10);
    if (callCount >= 5) {
      console.warn('Maximum visitor token API calls reached.');
      return null;
    }

    const visitorId = await getOrCreateVisitorId();
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
    localStorage.setItem('visitorSessionToken', data.token);

    // Increment the call count
    localStorage.setItem('visitorTokenApiCallCount', (callCount + 1).toString());

    return data.token;
  } catch (error) {
    console.warn(error);
    return null;
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

  // --- Advanced: Detect location and banner type ---
  let country = null;
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
      if (!data.bannerType) {
        return null;
      }
      country = data.country;
      return data;
    } catch (error) {
      console.log(error)
      return null;
    }
  }

  // --- Advanced: Encrypt and save consent preferences to server ---
  async function saveConsentStateToServer(preferences, cookieDays) {
    try {
      const clientId = window.location.hostname;
      const visitorId = localStorage.getItem("visitorId");
      const policyVersion = "1.2";
      const timestamp = new Date().toISOString();
      const sessionToken = localStorage.getItem("visitorSessionToken");
      if (!sessionToken) return;

      // Encryption
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
        encoder.encode(JSON.stringify(preferences))
      );
      const rawKey = await crypto.subtle.exportKey("raw", key);
      const b64Key = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
      const b64IV = btoa(String.fromCharCode(...iv));
      const b64EncryptedPreferences = btoa(String.fromCharCode(...new Uint8Array(encryptedPreferences)));

      const payload = {
        clientId,
        visitorId,
        preferences: {
          encryptedPreferences: b64EncryptedPreferences,
          encryptionKey: { key: b64Key, iv: b64IV }
        },
        policyVersion,
        timestamp,
        country,
        bannerType: preferences.bannerType,
        expiresAtTimestamp: Date.now() + (cookieDays * 24 * 60 * 60 * 1000),
        expirationDurationDays: cookieDays,
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
      console.error("Error in saveConsentStateToServer:", error);
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
      console.log(error);
    }
  }

  // --- Main ---
  document.addEventListener('DOMContentLoaded', async function() {
    checkConsentExpiration();
    hideAllBanners();
    let canPublish = false;
    let isStaging = false;
    try {
      const token = await getVisitorSessionToken();
      if (!token) {
        setTimeout(() => location.reload(), 2000);
        return;
      }
      if (!localStorage.getItem('visitorSessionToken')) {
        localStorage.setItem('visitorSessionToken', token);
      }
      canPublish = await checkPublishingStatus();
      isStaging = isStagingHostname();
      if (!canPublish && !isStaging) {
        removeConsentElements();
        return;
      }
    } catch (error) {
      console.warn("Initialization error:", error);
      setTimeout(() => location.reload(), 2000);
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
      // Detect which banner to show
      const locationData = await detectLocationAndGetBannerType();
      const consentGiven = localStorage.getItem("consent-given");
      let cookieDays = await fetchCookieExpirationDays();
      // On load: apply preferences if already set
      const prefs = getConsentPreferences();
      updatePreferenceForm(prefs);
      if (!consentGiven) {
        if (locationData && locationData.bannerType === "CCPA") {
          enableScriptsByCategories(['Analytics', 'Marketing', 'Personalization']);
          setConsentState({ Analytics: true, Marketing: true, Personalization: true }, cookieDays);
          showBanner(banners.ccpa);
          hideBanner(banners.consent);
        } else {
          showBanner(banners.consent);
          hideBanner(banners.ccpa);
        }
      } else {
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
          enableScriptsByCategories(Object.keys(preferences).filter(k => preferences[k]));
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          hideBanner(banners.main);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays);
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
          blockScriptsByCategory();
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          hideBanner(banners.main);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays);
          updatePreferenceForm(preferences);
        };
      }
      // Do Not Share (CCPA)
      const doNotShareBtn = qid('do-not-share-link');
      if (doNotShareBtn) {
        doNotShareBtn.onclick = async function(e) {
          e.preventDefault();
          const preferences = { Analytics: false, Marketing: false, Personalization: false, bannerType: locationData ? locationData.bannerType : undefined };
          setConsentState(preferences, cookieDays);
          blockScriptsByCategory();
          hideBanner(banners.ccpa);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays);
          updatePreferenceForm(preferences);
        };
      }
      // Preferences button (show preferences panel)
      const preferencesBtn = qid('preferences-btn');
      if (preferencesBtn) {
        preferencesBtn.onclick = function(e) {f
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
          blockScriptsByCategory();
          enableScriptsByCategories(Object.keys(preferences).filter(k => preferences[k]));
          hideBanner(banners.main);
          hideBanner(banners.consent);
          hideBanner(banners.ccpa);
          localStorage.setItem("consent-given", "true");
          await saveConsentStateToServer(preferences, cookieDays);
          updatePreferenceForm(preferences);
        };
      }
      // Cancel button (go back to main banner)
      const cancelBtn = qid('cancel-btn');
      if (cancelBtn) {
        cancelBtn.onclick = function(e) {
          e.preventDefault();
          hideBanner(banners.main);
          showBanner(banners.consent);
        };
      }
      // Toggle consent button
      const toggleConsentBtn = qid('toggle-consent-btn');
      if (toggleConsentBtn) {
        toggleConsentBtn.onclick = function(e) {
          e.preventDefault();
          // Show the main consent banner (GDPR or CCPA based on location)
          if (locationData && locationData.bannerType === "CCPA") {
            showBanner(banners.ccpa);
            hideBanner(banners.consent);
          } else {
            showBanner(banners.consent);
            hideBanner(banners.ccpa);
          }
          hideBanner(banners.main);
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

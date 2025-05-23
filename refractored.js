(function () {
  // Helper: set a cookie
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

  // Helper: get a cookie
  function getConsentCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  // Block all scripts by category (except Necessary)
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

  // Enable scripts for allowed categories
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

  // Google Consent Mode update
  function updateGtagConsent(granted) {
    if (typeof gtag === "function") {
      gtag('consent', 'update', {
        'analytics_storage': granted ? 'granted' : 'denied',
        'functionality_storage': granted ? 'granted' : 'denied',
        'ad_storage': 'denied',
        'ad_personalization': 'denied',
        'ad_user_data': 'denied',
        'personalization_storage': 'denied',
        'security_storage': 'granted'
      });
    }
  }

  // Consent state management
  function setConsentState(preferences) {
    Object.keys(preferences).forEach(function(category) {
      setConsentCookie('cb-consent-' + category.toLowerCase() + '_storage', preferences[category] ? 'true' : 'false', 365);
    });
    // Update Google Consent Mode for Analytics
    if ('Analytics' in preferences) {
      updateGtagConsent(preferences.Analytics);
    }
  }

  // Get preferences from cookies
  function getConsentPreferences() {
    return {
      Analytics: getConsentCookie('cb-consent-analytics_storage') === 'true',
      Marketing: getConsentCookie('cb-consent-marketing_storage') === 'true',
      Personalization: getConsentCookie('cb-consent-personalization_storage') === 'true'
    };
  }

  // Accept all
  function acceptAll() {
    var preferences = { Analytics: true, Marketing: true, Personalization: true };
    setConsentState(preferences);
    enableScriptsByCategories(['Analytics', 'Marketing', 'Personalization']);
    hideBanner();
  }

  // Reject all (block all except Necessary)
  function rejectAll() {
    var preferences = { Analytics: false, Marketing: false, Personalization: false };
    setConsentState(preferences);
    blockScriptsByCategory();
    hideBanner();
  }

  // Show/hide banner
  function showBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'flex';
  }
  function hideBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'none';
  }

  // On load: block all except Necessary, show banner if not decided
  document.addEventListener('DOMContentLoaded', function() {
    var prefs = getConsentPreferences();
    if (prefs.Analytics || prefs.Marketing || prefs.Personalization) {
      // Enable scripts for allowed categories
      var allowed = [];
      Object.keys(prefs).forEach(function(cat) {
        if (prefs[cat]) allowed.push(cat);
      });
      enableScriptsByCategories(allowed);
      // Update Google Consent Mode for Analytics
      updateGtagConsent(prefs.Analytics);
      hideBanner();
    } else {
      blockScriptsByCategory();
      updateGtagConsent(false);
      showBanner();
    }

    // Accept button
    var acceptBtn = document.getElementById('accept-btn');
    if (acceptBtn) {
      acceptBtn.onclick = function(e) {
        e.preventDefault();
        acceptAll();
      };
    }
     // Accept button
    var toggleBtn = document.getElementById('toggle-consent-btn');
    if (toggleBtn) {
      toggleBtn.onclick = function(e) {
        e.preventDefault();
        showBanner();
      };
    }

    // Decline button
    var declineBtn = document.getElementById('decline-btn');
    if (declineBtn) {
      declineBtn.onclick = function(e) {
        e.preventDefault();
        rejectAll();
      };
    }
  });
})();

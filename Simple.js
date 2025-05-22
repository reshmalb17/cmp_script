
(function() {
  // Helper to set a cookie
  function setConsentCookie(name, value, days) {
    let expires = "";
    if (days) {
      const date = new Date();
      date.setTime(date.getTime() + (days*24*60*60*1000));
      expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + value + expires + "; path=/";
  }
  // Helper to get a cookie
  function getConsentCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  // Set all cb-consent-* cookies and update Google Consent Mode
  function setConsentState(granted) {
    setConsentCookie('cb-consent-analytics_storage', granted ? 'true' : 'false', 365);
    setConsentCookie('cb-consent-functionality_storage', granted ? 'true' : 'false', 365);
    setConsentCookie('cb-consent-ad_storage', 'false', 365);
    setConsentCookie('cb-consent-ad_personalization', 'false', 365);
    setConsentCookie('cb-consent-ad_user_data', 'false', 365);
    setConsentCookie('cb-consent-personalization_storage', 'false', 365);
    setConsentCookie('cb-consent-security_storage', 'true', 365);

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

  // Block GA scripts by changing their type
  function blockGAScripts() {
    var scripts = document.querySelectorAll('script[src*="googletagmanager.com/gtag/js"], script[src*="google-analytics.com/analytics.js"]');
    scripts.forEach(function(script) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-consent', 'true');
      }
    });
  }

  // Restore GA scripts on consent
  function enableGAScripts() {
    var scripts = document.querySelectorAll('script[data-blocked-by-consent="true"]');
    scripts.forEach(function(oldScript) {
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

  // Show/hide banner
  function showBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'flex';
  }
  function hideBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'none';
  }

  // On load: check consent and act accordingly
  var consent = getConsentCookie('cb-consent-analytics_storage');
  if (consent === 'true') {
    setConsentState(true);
    enableGAScripts();
    hideBanner();
  } else if (consent === 'false') {
    setConsentState(false);
    blockGAScripts();
    hideBanner();
  } else {
    blockGAScripts();
    showBanner();
  }

  // Accept button
  var acceptBtn = document.getElementById('accept-btn');
  if (acceptBtn) {
    acceptBtn.onclick = function(e) {
      e.preventDefault();
      setConsentState(true);
      enableGAScripts();
      hideBanner();
    };
  }

  // Decline button
  var declineBtn = document.getElementById('decline-btn');
  if (declineBtn) {
    declineBtn.onclick = function(e) {
      e.preventDefault();
      setConsentState(false);
      blockGAScripts();
      hideBanner();
    };
  }

  // Also block GA scripts added dynamically
  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
        if (node.tagName === 'SCRIPT' && (node.src && (node.src.includes('googletagmanager.com/gtag/js') || node.src.includes('google-analytics.com/analytics.js')))) {
          if (getConsentCookie('cb-consent-analytics_storage') !== 'true') {
            node.type = 'text/plain';
            node.setAttribute('data-blocked-by-consent', 'true');
          }
        }
      });
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();

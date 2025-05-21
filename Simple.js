<script>
(function() {
  function setCookie(name, value, days) {
    let expires = "";
    if (days) {
      const date = new Date();
      date.setTime(date.getTime() + (days*24*60*60*1000));
      expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
  }
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  function blockGAScripts() {
    var scripts = document.querySelectorAll('script[src*="googletagmanager.com/gtag/js"], script[src*="google-analytics.com/analytics.js"]');
    scripts.forEach(function(script) {
      if (script.type !== 'text/plain') {
        script.type = 'text/plain';
        script.setAttribute('data-blocked-by-consent', 'true');
      }
    });
  }

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

  function showBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'flex';
  }
  function hideBanner() {
    var banner = document.getElementById('consent-banner');
    if (banner) banner.style.display = 'none';
  }

  // On load: block GA if no consent
  if (getCookie('cookie_consent_ga') === 'yes') {
    enableGAScripts();
    hideBanner();
  } else if (getCookie('cookie_consent_ga') === 'no') {
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
      setCookie('cookie_consent_ga', 'yes', 365);
      enableGAScripts();
      hideBanner();
    };
  }

  // Decline button
  var declineBtn = document.getElementById('decline-btn');
  if (declineBtn) {
    declineBtn.onclick = function(e) {
      e.preventDefault();
      setCookie('cookie_consent_ga', 'no', 365);
      blockGAScripts();
      hideBanner();
    };
  }

  // Also block GA scripts added dynamically
  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      mutation.addedNodes.forEach(function(node) {
        if (node.tagName === 'SCRIPT' && (node.src && (node.src.includes('googletagmanager.com/gtag/js') || node.src.includes('google-analytics.com/analytics.js')))) {
          if (getCookie('cookie_consent_ga') !== 'yes') {
            node.type = 'text/plain';
            node.setAttribute('data-blocked-by-consent', 'true');
          }
        }
      });
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
</script>

( function(){
// Google Analytics / gtag / GTM
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('consent', 'default', {'ad_storage': 'denied','analytics_storage': 'denied'});

// Microsoft Clarity
window.clarity = window.clarity || function(){(window.clarity.q = window.clarity.q || []).push(arguments);};
window.clarity.consent = false;

// Facebook Pixel
window.fbq = window.fbq || function(){(window.fbq.callMethod ? window.fbq.callMethod : window.fbq.queue.push).apply(window.fbq, arguments);};
window.fbq.queue = window.fbq.queue || [];
window.fbq('consent', 'revoke');

// Matomo
window._paq = window._paq || [];
window._paq.push(['requireConsent']);
window._paq.push(['setConsentGiven', false]);

// Plausible
window.plausible = window.plausible || function(){(window.plausible.q = window.plausible.q || []).push(arguments);};
window.plausible('consent', false);

// Amplitude
window.amplitude = window.amplitude || {};
window.amplitude.getInstance = function(){return {setOptOut:function(optOut){window.amplitude.optedOut=optOut;}}};
window.amplitude.getInstance().setOptOut(true);

// LinkedIn
window._linkedin_data_partner_ids = window._linkedin_data_partner_ids || [];
window.lintrk = window.lintrk || function() {};
window.lintrk('consent', false);

// Twitter
window.twq = window.twq || function(){(window.twq.exe ? window.twq.exe : window.twq.queue.push).apply(window.twq, arguments);};
window.twq.queue = window.twq.queue || [];
window.twq('consent', 'revoke');

// TikTok
window.ttq = window.ttq || function(){(window.ttq.queue = window.ttq.queue || []).push(arguments);};
window.ttq('consent', 'revoke');

// Pinterest
window.pintrk = window.pintrk || function(){(window.pintrk.queue = window.pintrk.queue || []).push(arguments);};
window.pintrk('consent', 'revoke');

// Outbrain
window.OB_ADV_ID = window.OB_ADV_ID || [];
window.obApi = window.obApi || function(){(window.obApi.queue = window.obApi.queue || []).push(arguments);};
window.obApi('consent', false);

// Taboola
window._tfa = window._tfa || [];
window._tfa.push({notify: 'consent', value: false});

// HubSpot
window._hsq = window._hsq || [];
window._hsq.push(['doNotTrack', {track: false}]);

// Zendesk
window.zESettings = window.zESettings || {};
window.zESettings.consent = false;

// Drift
window.drift = window.drift || function(){(window.drift.queue = window.drift.queue || []).push(arguments);};
window.drift('consent', false);

// Intercom
window.intercomSettings = window.intercomSettings || {};
window.intercomSettings.consent = false;

// Hotjar
window.hj = window.hj || function(){(window.hj.q = window.hj.q || []).push(arguments);};
window.hj('consent', false);

// Loader for your main consent script
(async function() {
  var script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/gh/reshmalb17/cmp_script@65ada01/subscription.js'; // <-- your CDN link here
  script.async = true;
  document.head.appendChild(script);
})();
})();

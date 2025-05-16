
        (function() {
          // Block all tools before anything else loads
          const blockAllTools = () => {
            // --- Google Analytics / gtag / GTM ---
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('consent', 'default', {'ad_storage': 'denied','analytics_storage': 'denied'});

            // --- Microsoft Clarity ---
            window.clarity = window.clarity || function(){(window.clarity.q = window.clarity.q || []).push(arguments);};
            window.clarity.consent = false;

            // --- Facebook Pixel ---
            window.fbq = window.fbq || function(){(window.fbq.q = window.fbq.q || []).push(arguments);};
            window.fbq('consent', 'revoke');

            // --- Matomo ---
            window._paq = window._paq || [];
            window._paq.push(['requireConsent']);
            window._paq.push(['setConsentGiven', false]);

            // --- Plausible ---
            window.plausible = window.plausible || function(){(window.plausible.q = window.plausible.q || []).push(arguments);};
            window.plausible('consent', false);

            // --- Amplitude ---
            window.amplitude = window.amplitude || {};
            window.amplitude.getInstance = window.amplitude.getInstance || function(){return {setOptOut:function(optOut){window.amplitude.optedOut=optOut;}}};
            window.amplitude.getInstance().setOptOut(true);

            // --- LinkedIn Insight Tag ---
            window._linkedin_data_partner_ids = window._linkedin_data_partner_ids || [];
            window.lintrk = window.lintrk || function(){(window.lintrk.q = window.lintrk.q || []).push(arguments);};
            window.lintrk('consent', false);

            // --- Twitter Pixel ---
            window.twq = window.twq || function(){(window.twq.q = window.twq.q || []).push(arguments);};
            window.twq('consent', 'revoke');

            // --- TikTok Pixel ---
            window.ttq = window.ttq || function(){(window.ttq.q = window.ttq.q || []).push(arguments);};
            window.ttq('consent', 'revoke');

            // --- Pinterest Tag ---
            window.pintrk = window.pintrk || function(){(window.pintrk.q = window.pintrk.q || []).push(arguments);};
            window.pintrk('consent', 'revoke');

            // --- Outbrain ---
            window.OB_ADV_ID = window.OB_ADV_ID || [];
            window.obApi = window.obApi || function(){(window.obApi.q = window.obApi.q || []).push(arguments);};
            window.obApi('consent', false);

            // --- Taboola ---
            window._tfa = window._tfa || [];
            window._tfa.push({notify: 'consent', value: false});

            // --- HubSpot ---
            window._hsq = window._hsq || [];
            window._hsq.push(['doNotTrack', {track: false}]);

            // --- Zendesk ---
            window.zESettings = window.zESettings || {};
            window.zESettings.consent = false;

            // --- Drift ---
            window.drift = window.drift || function(){(window.drift.q = window.drift.q || []).push(arguments);};
            window.drift('consent', false);

            // --- Intercom ---
            window.intercomSettings = window.intercomSettings || {};
            window.intercomSettings.consent = false;

            // --- Hotjar ---
            window.hj = window.hj || function(){(window.hj.q = window.hj.q || []).push(arguments);};
            window.hj('consent', false);
          };

          // Execute blocking immediately
          blockAllTools();

          // Load the main script
          const script = document.createElement('script');
          script.src = 'https://cdn.jsdelivr.net/gh/reshmalb17/cmp_script@65ada01/subscription.js';
          script.async = true;
          script.setAttribute('data-consentbit-src', 'https://cdn.jsdelivr.net/gh/reshmalb17/cmp_script@65ada01/subscription.js');
          document.head.appendChild(script);
        })();
      

(async function () {
    const existing_Scripts = {};
    let scriptIdCounter = 0;
    let isLoadingState = false;
    let consentState = {};
    let observer = null;
    let isInitialized = false;
    let currentBannerType = null;
    let country = null;
    let categorizedScripts = null;
    let initialBlockingEnabled = true;

    const suspiciousPatterns = [
      {
        pattern: /collect|plausible.io|googletagmanager|google-analytics|gtag|analytics|zoho|track|metrics|pageview|stat|trackpageview|amplitude|amplitude.com/i,
        category: "Analytics"
      },
      {
        pattern: /facebook|meta|fbevents|linkedin|twitter|pinterest|tiktok|snap|reddit|quora|outbrain|taboola|sharethrough|matomo/i,
        category: "Marketing"
      },
      {
        pattern: /optimizely|hubspot|marketo|pardot|salesforce|intercom|drift|zendesk|freshchat|tawk|livechat/i,
        category: "Personalization"
      }
    ];

    const EncryptionUtils = {
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
            let keyMaterial = rawKey;
            if (Array.isArray(rawKey)) {
                 keyMaterial = new Uint8Array(rawKey);
            } else if (!(rawKey instanceof ArrayBuffer) && !ArrayBuffer.isView(rawKey)) {
                 throw new Error("Invalid key format for importKey");
            }

            return await crypto.subtle.importKey(
                'raw',
                keyMaterial,
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
            return encrypted;
        },

        async decrypt(encryptedData, key, iv) {
            let dataBuffer = encryptedData;
            if (typeof encryptedData === 'string') {
                 dataBuffer = base64ToArrayBuffer(encryptedData);
            } else if (!(encryptedData instanceof ArrayBuffer) && !ArrayBuffer.isView(encryptedData)) {
                 throw new Error("Invalid encryptedData format for decrypt");
            }

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                dataBuffer
            );
            return new TextDecoder().decode(decrypted);
        }
    };

    function arrayBufferToBase64(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary_string = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function isTokenExpired(token) {
        try {
            const [headerBase64, payloadBase64, signatureBase64] = token.split('.');
            if (!payloadBase64 || !signatureBase64) {
                return true;
            }
            const decoder = new TextDecoder();
            const payloadString = decoder.decode(base64ToArrayBuffer(payloadBase64.replace(/-/g, '+').replace(/_/g, '/')));
            const payload = JSON.parse(payloadString);

            if (typeof payload.exp !== 'number') {
                return true;
            }

            const isExpired = payload.exp < Math.floor(Date.now() / 1000);
            return isExpired;
        } catch (error) {
            return true;
        }
    }

    async function cleanHostname(hostname) {
        let cleaned = hostname.replace(/^www\./, '');
        return cleaned;
    }

    async function getOrCreateVisitorId() {
        let visitorId = localStorage.getItem('visitorId');
        if (!visitorId) {
            visitorId = crypto.randomUUID();
            localStorage.setItem('visitorId', visitorId);
        }
        return visitorId;
    }

    function getClientIdentifier() {
        return window.location.hostname;
    }

    async function detectLocationAndGetBannerType() {
      try {
          const sessionToken = localStorage.getItem('visitorSessionToken');
          if (!sessionToken || isTokenExpired(sessionToken)) {
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
              mode: 'cors'
          });

          if (!response.ok) {
              await response.text();
              return null;
          }

          const data = await response.json();

          if (!data || typeof data !== 'object' || !data.bannerType) {
              return null;
          }
          country = data.country;
          return { bannerType: data.bannerType, country: data.country };
      } catch (error) {
          return null;
      }
    }

    function normalizeUrl(url) {
        if (!url) return null;
        try {
           const urlObj = new URL(url, window.location.origin);
           let normalized = urlObj.hostname.replace(/^www\./, '') + urlObj.pathname;
           normalized = normalized.replace(/\/$/, '');
           return normalized;
        } catch (e) {
           return url.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/$/, '');
        }
    }

    function getScriptKey(script) {
        if (script.src) {
            return normalizeUrl(script.src);
        } else if (script.textContent) {
             const content = script.textContent.trim();
             if (!content) return null;
             return `inline_${content.length}_${content.slice(0,15)}_${content.slice(-15)}`;
        }
        return null;
    }

    function isScriptAlreadyBlocked(script) {
        if (script.hasAttribute('data-consentbit-id')) {
            return true;
        }
        if (script.type === 'text/plain') {
             if (script.hasAttribute('data-consentbit-id')) {
                 return true;
             }
             return false;
        }
        const key = getScriptKey(script);
        if (!key) return false;
        return Object.values(existing_Scripts).some(info => info.key === key);
    }

    function createPlaceholder(originalScript, category = "uncategorized") {
      const placeholder = document.createElement("script");
      const uniqueId = `consentbit-script-${scriptIdCounter++}`;
      const scriptKey = getScriptKey(originalScript);

      if (!scriptKey) {
           return null;
      }

      if (Object.values(existing_Scripts).some(info => info.key === scriptKey)) {
          if (originalScript.parentNode && document.contains(originalScript)) {
               originalScript.parentNode.removeChild(originalScript);
          }
          return null;
      }

      placeholder.type = "text/plain";
      placeholder.setAttribute("data-consentbit-id", uniqueId);
      placeholder.setAttribute("data-category", category.toLowerCase());
      if (originalScript.src) {
           placeholder.setAttribute("data-original-src", originalScript.src);
      }

      const scriptInfo = {
          id: uniqueId,
          key: scriptKey,
          category: category.split(',').map(c => c.trim().toLowerCase()),
          async: originalScript.async,
          defer: originalScript.defer,
          type: originalScript.type || "text/javascript",
          originalAttributes: {}
      };

      if (originalScript.src) {
          scriptInfo.src = originalScript.src;
      } else {
          scriptInfo.content = originalScript.textContent || "";
      }

      for (const attr of originalScript.attributes) {
          const lowerCaseAttrName = attr.name.toLowerCase();
          if (!['src', 'type', 'async', 'defer', 'data-category', 'data-consentbit-id', 'data-original-src'].includes(lowerCaseAttrName)) {
              scriptInfo.originalAttributes[attr.name] = attr.value;
          }
      }

      existing_Scripts[uniqueId] = scriptInfo;

      return placeholder;
    }

    function findCategoryByPattern(text) {
        if (!text) return null;
        const cleanedText = text.replace(/\s+/g, "");
        for (const { pattern, category } of suspiciousPatterns) {
            if (pattern.test(cleanedText)) {
                return category;
            }
        }
        return null;
    }

    async function loadCategorizedScripts() {
        try {
            const sessionToken = localStorage.getItem('visitorSessionToken');
            if (!sessionToken || isTokenExpired(sessionToken)) {
                return [];
            }

            const visitorId = await getOrCreateVisitorId();
            const siteName = window.location.hostname.replace(/^www\./, '').split('.')[0];

            const { key: requestKey, iv: requestIv } = await EncryptionUtils.generateKey();
            const requestIvBytes = new Uint8Array(requestIv);
            const requestData = { siteName, visitorId, userAgent: navigator.userAgent };

            const encryptedRequestBuffer = await EncryptionUtils.encrypt(JSON.stringify(requestData), requestKey, requestIvBytes);
            const b64EncryptedRequest = arrayBufferToBase64(encryptedRequestBuffer);

            const rawRequestKey = await crypto.subtle.exportKey('raw', requestKey);
            const requestKeyArray = new Uint8Array(32);
            requestKeyArray.set(new Uint8Array(rawRequestKey).slice(0, 32));
            const b64RequestKey = arrayBufferToBase64(requestKeyArray.buffer);
            const b64RequestIV = arrayBufferToBase64(requestIvBytes.buffer);

            const apiUrl = 'https://cb-server.web-8fb.workers.dev/api/cmp/script-category';
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${sessionToken}`,
                    'X-Request-ID': crypto.randomUUID(),
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify({
                    encryptedData: b64EncryptedRequest,
                    key: b64RequestKey,
                    iv: b64RequestIV
                }),
                mode: 'cors'
            });

            if (!response.ok) {
                await response.text();
                return [];
            }

            const data = await response.json();

            if (data.encryptedData && data.key && data.iv) {
                try {
                     const responseKeyBytes = base64ToArrayBuffer(data.key);
                     const responseIvBytes = base64ToArrayBuffer(data.iv);

                     if (responseKeyBytes.byteLength !== 32 || responseIvBytes.byteLength !== 12) {
                          return [];
                     }

                    const responseKey = await EncryptionUtils.importKey(
                        new Uint8Array(responseKeyBytes), ['decrypt']
                    );

                    const decryptedData = await EncryptionUtils.decrypt(
                        base64ToArrayBuffer(data.encryptedData),
                        responseKey,
                        new Uint8Array(responseIvBytes)
                    );

                    const responseObj = JSON.parse(decryptedData);
                    categorizedScripts = Array.isArray(responseObj.scripts) ? responseObj.scripts : [];
                    return categorizedScripts;
                } catch (decryptionError) {
                     return [];
                }
            } else if (Array.isArray(data.scripts)) {
                 categorizedScripts = data.scripts;
                 return categorizedScripts;
            } else {
                return [];
            }
        } catch (error) {
            return [];
        }
      }

    function _blockSingleScriptNode(scriptNode, categories) {
        if (isScriptAlreadyBlocked(scriptNode)) {
             return;
        }
        const placeholder = createPlaceholder(scriptNode, categories.join(','));
        if (placeholder && scriptNode.parentNode && document.contains(scriptNode)) {
             try {
                  scriptNode.parentNode.replaceChild(placeholder, scriptNode);
             } catch (error) {
             }
        } else if (placeholder && !scriptNode.parentNode) {
        } else if (placeholder && !document.contains(scriptNode)) {
        }
    }

    async function _updateObserverState() {
         const prefs = consentState;
         const needsBlocking = !prefs ||
                              prefs.Marketing === false ||
                              prefs.Personalization === false ||
                              prefs.Analytics === false ||
                              (prefs.ccpa?.DoNotShare === true || prefs.DoNotShare === true);

        if (needsBlocking && !observer) {

            const categorizedScriptsList = categorizedScripts || await loadCategorizedScripts();
            const serverCategoriesMap = new Map();
            categorizedScriptsList.forEach(s => {
                const categories = Array.isArray(s.category)
                    ? s.category.map(c => String(c).trim().toLowerCase())
                    : (String(s.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean));
                if (s.src) {
                    const normalizedSrc = normalizeUrl(s.src);
                    if (normalizedSrc) serverCategoriesMap.set(normalizedSrc, categories);
                }
            });

            observer = new MutationObserver((mutationsList) => {
                const currentPrefs = consentState;
                const blockingStillNeeded = !currentPrefs || currentPrefs.Marketing === false || currentPrefs.Personalization === false || currentPrefs.Analytics === false || (currentPrefs.ccpa?.DoNotShare === true || currentPrefs.DoNotShare === true);

                if (!blockingStillNeeded) {
                    if (observer) {
                        observer.disconnect();
                        observer = null;
                    }
                    return;
                }

                for (const mutation of mutationsList) {
                   for (const node of mutation.addedNodes) {
                       if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'SCRIPT') {
                           if (node.type !== 'text/plain' && !node.hasAttribute('data-consentbit-id') && !isScriptAlreadyBlocked(node)) {

                               const nodeKey = getScriptKey(node);
                               if (!nodeKey) continue;

                               let nodeCategories = [];
                               let nodeCatSource = 'none';

                               if (node.src) {
                                   const normalizedSrc = normalizeUrl(node.src);
                                   if (serverCategoriesMap.has(normalizedSrc)) {
                                       nodeCategories = serverCategoriesMap.get(normalizedSrc);
                                       nodeCatSource = 'server';
                                   } else {
                                       const patternCat = findCategoryByPattern(node.src);
                                       if (patternCat) { nodeCategories = [patternCat.toLowerCase()]; nodeCatSource = 'pattern (src)'; }
                                   }
                               } else if (node.textContent) {
                                    const patternCat = findCategoryByPattern(node.textContent);
                                    if (patternCat) { nodeCategories = [patternCat.toLowerCase()]; nodeCatSource = 'pattern (inline)'; }
                               }

                               if (nodeCategories.length > 0 && !_isScriptAllowed(nodeCategories, currentPrefs)) {
                                   _blockSingleScriptNode(node, nodeCategories);
                               }
                           }
                       }
                   }
               }
            });

            observer.observe(document.documentElement, { childList: true, subtree: true });

        } else if (!needsBlocking && observer) {
             observer.disconnect();
             observer = null;
        }
    }

    async function scanAndBlockScripts() {
        const categorizedScriptsList = categorizedScripts || await loadCategorizedScripts();

        const serverCategoriesMap = new Map();
        categorizedScriptsList.forEach(s => {
            const categories = Array.isArray(s.category)
                ? s.category.map(c => String(c).trim().toLowerCase())
                : (String(s.category || '').split(',').map(c => c.trim().toLowerCase()).filter(Boolean));
            if (s.src) {
                const normalizedSrc = normalizeUrl(s.src);
                if (normalizedSrc) serverCategoriesMap.set(normalizedSrc, categories);
            }
        });

        const scriptsToCheck = Array.from(document.querySelectorAll("script:not([type='text/plain']):not([data-consentbit-id]), script[type='text/plain']:not([data-consentbit-id])"));

        scriptsToCheck.forEach(script => {
             if (script.type === 'text/plain' && script.hasAttribute('data-consentbit-id')) return;
             if (isScriptAlreadyBlocked(script)) return;

            const scriptKey = getScriptKey(script);
            if (!scriptKey) return;

            let scriptCategories = [];
            let categorySource = 'none';

            if (script.src) {
                const normalizedSrc = normalizeUrl(script.src);
                if (serverCategoriesMap.has(normalizedSrc)) {
                    scriptCategories = serverCategoriesMap.get(normalizedSrc);
                    categorySource = 'server';
                } else {
                    const patternCategory = findCategoryByPattern(script.src);
                    if (patternCategory) {
                        scriptCategories = [patternCategory.toLowerCase()];
                        categorySource = 'pattern (src)';
                    }
                }
            } else if (script.textContent) {
                 const patternCategory = findCategoryByPattern(script.textContent);
                 if (patternCategory) {
                     scriptCategories = [patternCategory.toLowerCase()];
                     categorySource = 'pattern (inline)';
                 }
            }

            if (scriptCategories.length > 0) {
                _blockSingleScriptNode(script, scriptCategories);
            }
        });

        await _updateObserverState();
    }

    function buildConsentPreferences(preferences, country, timestamp) {
        const flatPrefs = {
          Necessary: true,
          Marketing: preferences.Marketing || false,
          Personalization: preferences.Personalization || false,
          Analytics: preferences.Analytics || false,
          DoNotShare: preferences.ccpa?.DoNotShare ?? preferences.DoNotShare ?? false,
          consentTimestamp: timestamp,
          consentPolicyVersion: "1.2",
          consentCountry: country || 'Unknown',
          bannerType: currentBannerType || 'Unknown'
        };
        return flatPrefs;
    }

    async function storeEncryptedConsentLocally(preferences, country, timestamp) {
      try {
          const consentPreferencesToStore = buildConsentPreferences(preferences, country, timestamp);

          const { key, iv } = await EncryptionUtils.generateKey();
          const ivBytes = new Uint8Array(iv);

          const encryptedPreferencesBuffer = await EncryptionUtils.encrypt(
              JSON.stringify(consentPreferencesToStore),
              key,
              ivBytes
          );

          const rawKey = await crypto.subtle.exportKey('raw', key);
          const keyArray = new Uint8Array(32);
          const exportedKeyBytes = new Uint8Array(rawKey);
          keyArray.set(exportedKeyBytes.slice(0, 32));

          localStorage.setItem("consent-given", "true");
          localStorage.setItem("consent-preferences", JSON.stringify({
              encryptedData: arrayBufferToBase64(encryptedPreferencesBuffer),
              iv: Array.from(ivBytes),
              key: Array.from(keyArray)
          }));

          localStorage.setItem("consent-policy-version", consentPreferencesToStore.consentPolicyVersion);
          localStorage.setItem("consent-timestamp", consentPreferencesToStore.consentTimestamp);

          consentState = consentPreferencesToStore;

      } catch (error) {
          localStorage.removeItem("consent-preferences");
          localStorage.removeItem("consent-given");
          consentState = {};
      }
    }

    async function _getDecryptedPreferences() {
      try {
          const savedPreferencesRaw = localStorage.getItem("consent-preferences");
          const consentGiven = localStorage.getItem("consent-given") === "true";

          if (!savedPreferencesRaw || !consentGiven) {
              localStorage.removeItem("consent-preferences");
              localStorage.removeItem("consent-given");
              return null;
          }

          const savedPreferences = JSON.parse(savedPreferencesRaw);
          if (!savedPreferences?.encryptedData || !savedPreferences.key || !savedPreferences.iv) {
               localStorage.removeItem("consent-preferences");
               localStorage.removeItem("consent-given");
               return null;
          }

          const keyBytes = new Uint8Array(savedPreferences.key);
          if (keyBytes.length !== 32) {
              localStorage.removeItem("consent-preferences");
              localStorage.removeItem("consent-given");
              return null;
          }

          const ivBytes = new Uint8Array(savedPreferences.iv);
          if (ivBytes.length !== 12) {
               localStorage.removeItem("consent-preferences");
               localStorage.removeItem("consent-given");
               return null;
          }

          const key = await EncryptionUtils.importKey(keyBytes, ['decrypt']);

          const decryptedString = await EncryptionUtils.decrypt(
              base64ToArrayBuffer(savedPreferences.encryptedData),
              key,
              ivBytes
          );

          const decryptedPrefs = JSON.parse(decryptedString);
          if (typeof decryptedPrefs !== 'object' || decryptedPrefs === null) {
               throw new Error("Decrypted preferences are not a valid object.");
          }
          if (decryptedPrefs.Necessary === undefined) {
               decryptedPrefs.Necessary = true;
          }
          return decryptedPrefs;

      } catch (error) {
          localStorage.removeItem("consent-preferences");
          localStorage.removeItem("consent-given");
          return null;
      }
    }


    async function saveConsentState(preferences) {
      const clientId = getClientIdentifier();
      const visitorId = await getOrCreateVisitorId();
      const policyVersion = "1.2";
      const timestamp = new Date().toISOString();
      const sessionToken = localStorage.getItem("visitorSessionToken");

      await storeEncryptedConsentLocally(preferences, country, timestamp);

      if (!sessionToken || isTokenExpired(sessionToken)) {
        return;
      }

      try {
        const consentPreferencesForEncryption = buildConsentPreferences(preferences, country, timestamp);
        const prefsJson = JSON.stringify(consentPreferencesForEncryption);
        const visitorIdJson = JSON.stringify({ visitorId: visitorId });

        const { key, iv } = await EncryptionUtils.generateKey();
        const ivBytes = new Uint8Array(iv);

        const encryptedPreferencesBuffer = await EncryptionUtils.encrypt(prefsJson, key, ivBytes);
        const encryptedVisitorIdBuffer = await EncryptionUtils.encrypt(visitorIdJson, key, ivBytes);

        const rawKey = await crypto.subtle.exportKey("raw", key);
        const keyArray = new Uint8Array(32);
        const exportedKeyBytes = new Uint8Array(rawKey);
        keyArray.set(exportedKeyBytes.slice(0, 32));

        const b64Key = arrayBufferToBase64(keyArray.buffer);
        const b64IV = arrayBufferToBase64(ivBytes.buffer);
        const b64EncryptedPreferences = arrayBufferToBase64(encryptedPreferencesBuffer);
        const b64EncryptedVisitorId = arrayBufferToBase64(encryptedVisitorIdBuffer);

        const payload = {
          clientId,
          encryptedVisitorId: {
            encryptedPreferences: b64EncryptedVisitorId,
            encryptionKey: { key: b64Key, iv: b64IV }
          },
          preferences: {
            encryptedPreferences: b64EncryptedPreferences,
            encryptionKey: { key: b64Key, iv: b64IV }
          },
          policyVersion,
          timestamp,
          country,
          bannerType: currentBannerType,
          metadata: {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
          }
        };

        const response = await fetch("https://cb-server.web-8fb.workers.dev/api/cmp/consent", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${sessionToken}`,
          },
          body: JSON.stringify(payload),
          mode: 'cors'
        });

        await response.text();
        if (!response.ok) {
        } else {
        }
      } catch (error) {
      }
    }

    function showBanner(banner) {
        if (banner && typeof banner === 'object' && typeof banner.style !== 'undefined') {
          banner.style.display = "block";
           banner.classList.add("show-banner");
           banner.classList.remove("hidden");
        } else {
        }
    }

    function hideBanner(banner) {
        if (banner && typeof banner === 'object' && typeof banner.style !== 'undefined') {
          banner.style.display = "none";
           banner.classList.remove("show-banner");
           banner.classList.add("hidden");
        } else {
        }
    }

    async function updatePreferenceForm(state) {
        if (!state || typeof state !== 'object') {
             return;
        }

        const prefs = {
            Necessary: true,
            Marketing: state.Marketing ?? false,
            Personalization: state.Personalization ?? false,
            Analytics: state.Analytics ?? false,
            DoNotShare: state.ccpa?.DoNotShare ?? state.DoNotShare ?? false
        };

        const updateCheckbox = (selector, isChecked) => {
            const checkbox = document.querySelector(selector);
            if (checkbox) {
                checkbox.checked = isChecked;
            }
        };

        const necessaryGdpr = document.querySelector('#main-banner [data-consent-id="necessary-checkbox"]');
        if (necessaryGdpr) {
            necessaryGdpr.checked = true;
            necessaryGdpr.disabled = true;
        }
        updateCheckbox('#main-banner [data-consent-id="marketing-checkbox"]', prefs.Marketing);
        updateCheckbox('#main-banner [data-consent-id="personalization-checkbox"]', prefs.Personalization);
        updateCheckbox('#main-banner [data-consent-id="analytics-checkbox"]', prefs.Analytics);

        updateCheckbox('#main-consent-banner [data-consent-id="do-not-share-checkbox"]', prefs.DoNotShare);
    }

    function attachListener(id, event, handler) {
      const element = document.getElementById(id);
      if (element) {
          element.addEventListener(event, handler);
      } else {
      }
    }

    async function handleSimpleAccept(e) {
      e.preventDefault();
      const simpleBanner = document.getElementById("simple-consent-banner");
      const preferences = { Necessary: true, Marketing: true, Personalization: true, Analytics: true, ccpa: { DoNotShare: false } };
      await saveConsentState(preferences);
      await restoreAllowedScripts(preferences);
      await _updateObserverState();
      if (simpleBanner) hideBanner(simpleBanner);
      localStorage.setItem("consent-given", "true");
    }

    async function handleSimpleReject(e) {
      e.preventDefault();
      const simpleBanner = document.getElementById("simple-consent-banner");
      const preferences = { Necessary: true, Marketing: false, Personalization: false, Analytics: false, ccpa: { DoNotShare: true } };
      await saveConsentState(preferences);
      await _updateObserverState();
      if (simpleBanner) hideBanner(simpleBanner);
      localStorage.setItem("consent-given", "true");
    }

    function handleToggleConsent(e) {
      e.preventDefault();
      const consentBanner = document.getElementById("consent-banner");
      const ccpaBanner = document.getElementById("initial-consent-banner");
      const mainConsentBanner = document.getElementById("main-consent-banner");
      const mainBanner = document.getElementById("main-banner");

      const type = currentBannerType;

      if (consentBanner) hideBanner(consentBanner);
      if (ccpaBanner) hideBanner(ccpaBanner);
      if (mainConsentBanner) hideBanner(mainConsentBanner);
      if (mainBanner) hideBanner(mainBanner);

      const prefs = consentState;
      const consentGiven = localStorage.getItem("consent-given") === "true";

      if (consentGiven && prefs && Object.keys(prefs).length > 0) {
          if (type === 'CCPA') {
              if (mainConsentBanner) showBanner(mainConsentBanner);
          } else {
              if (mainBanner) showBanner(mainBanner);
          }
      } else {
          if (type === 'CCPA') {
              if (ccpaBanner) showBanner(ccpaBanner);
          } else {
              if (consentBanner) showBanner(consentBanner);
          }
      }
    }

    function handleDoNotShareLinkClick(e) {
      e.preventDefault();
      const ccpaBanner = document.getElementById("initial-consent-banner");
      const mainConsentBanner = document.getElementById("main-consent-banner");
      if (ccpaBanner) hideBanner(ccpaBanner);
      if (mainConsentBanner) showBanner(mainConsentBanner);
    }

    function handleCloseConsentBanner(e) {
      e.preventDefault();
      const banner = e.target.closest('.consent-banner-class');
      if (banner) {
         hideBanner(banner);
      } else {
         const mainConsentBanner = document.getElementById("main-consent-banner");
         const mainBanner = document.getElementById("main-banner");
         if (mainConsentBanner && mainConsentBanner.contains(e.target)) hideBanner(mainConsentBanner);
         if (mainBanner && mainBanner.contains(e.target)) hideBanner(mainBanner);
      }
    }

    async function handleAcceptAll(e) {
      e.preventDefault();
      await acceptAllCookies();
    }

    async function handleDeclineAll(e) {
      e.preventDefault();
      await blockAllCookies();
    }

    function handleShowPreferences(e) {
      e.preventDefault();
      const consentBanner = document.getElementById("consent-banner");
      const mainBanner = document.getElementById("main-banner");
      if(consentBanner) hideBanner(consentBanner);
      if(mainBanner) showBanner(mainBanner);
    }

    async function handleSaveGdprPreferences(e) {
      e.preventDefault();
      const marketingCheckbox = document.querySelector('#main-banner [data-consent-id="marketing-checkbox"]');
      const personalizationCheckbox = document.querySelector('#main-banner [data-consent-id="personalization-checkbox"]');
      const analyticsCheckbox = document.querySelector('#main-banner [data-consent-id="analytics-checkbox"]');
      const preferences = {
          Necessary: true,
          Marketing: marketingCheckbox?.checked || false,
          Personalization: personalizationCheckbox?.checked || false,
          Analytics: analyticsCheckbox?.checked || false,
          ccpa: { DoNotShare: consentState.ccpa?.DoNotShare ?? false }
      };
      try {
          await saveConsentState(preferences);
          await restoreAllowedScripts(preferences);
          await _updateObserverState();
      } catch (error) {
      }
      const consentBanner = document.getElementById("consent-banner");
      const mainBanner = document.getElementById("main-banner");
      if(consentBanner) hideBanner(consentBanner);
      if(mainBanner) hideBanner(mainBanner);
    }

    async function handleSaveCcpaPreferences(e) {
      e.preventDefault();
      const doNotShareCheckbox = document.querySelector('#main-consent-banner [data-consent-id="do-not-share-checkbox"]');
      const doNotShare = doNotShareCheckbox?.checked || false;

      const preferences = {
          Necessary: true,
          Marketing: !doNotShare,
          Personalization: !doNotShare,
          Analytics: !doNotShare,
          ccpa: { DoNotShare: doNotShare }
      };

      try {
          await saveConsentState(preferences);
          await restoreAllowedScripts(preferences);
          await _updateObserverState();
      } catch (error) {
      }

      const initialCcpaBanner = document.getElementById("initial-consent-banner");
      const mainCcpaBanner = document.getElementById("main-consent-banner");
      if(initialCcpaBanner) hideBanner(initialCcpaBanner);
      if(mainCcpaBanner) hideBanner(mainCcpaBanner);
    }

    async function handleCancelPreferences(e) {
      e.preventDefault();

      const mainBanner = document.getElementById("main-banner");
      const mainConsentBanner = document.getElementById("main-consent-banner");
      if (mainBanner) hideBanner(mainBanner);
      if (mainConsentBanner) hideBanner(mainConsentBanner);

      await updatePreferenceForm(consentState);
    }

    async function attachBannerHandlers() {
      const necessaryCheckbox = document.querySelector('[data-consent-id="necessary-checkbox"]');
      if (necessaryCheckbox) {
          necessaryCheckbox.checked = true;
          necessaryCheckbox.disabled = true;
      }

      attachListener("simple-accept", "click", handleSimpleAccept);
      attachListener("simple-reject", "click", handleSimpleReject);
      attachListener("toggle-consent-btn", "click", handleToggleConsent);
      attachListener("new-toggle-consent-btn", "click", handleToggleConsent);
      attachListener("do-not-share-link", "click", handleDoNotShareLinkClick);
      attachListener("close-consent-banner", "click", handleCloseConsentBanner);

      attachListener("accept-btn", "click", handleAcceptAll);
      attachListener("decline-btn", "click", handleDeclineAll);

      attachListener("preferences-btn", "click", handleShowPreferences);
      attachListener("save-preferences-btn", "click", handleSaveGdprPreferences);

      attachListener("save-btn", "click", handleSaveCcpaPreferences);

      attachListener("cancel-btn", "click", handleCancelPreferences);

    }

    async function initializeBannerVisibility() {
        const locationData = await detectLocationAndGetBannerType();
        currentBannerType = locationData?.bannerType;
        country = locationData?.country;
    }

    function initializeBanner() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', attachBannerHandlers);
        } else {
            attachBannerHandlers();
        }
    }

    async function acceptAllCookies() {
        const allAllowedPreferences = {
            Necessary: true, Marketing: true, Personalization: true, Analytics: true,
            ccpa: { DoNotShare: false }
        };
        await saveConsentState(allAllowedPreferences);
        await updatePreferenceForm(allAllowedPreferences);
        await restoreAllowedScripts(allAllowedPreferences);
        await _updateObserverState();

        hideBanner(document.getElementById("consent-banner"));
        hideBanner(document.getElementById("initial-consent-banner"));
        hideBanner(document.getElementById("main-banner"));
        hideBanner(document.getElementById("main-consent-banner"));
        hideBanner(document.getElementById("simple-consent-banner"));
    }

    async function blockAllCookies() {
      const rejectNonNecessaryPreferences = {
          Necessary: true, Marketing: false, Personalization: false, Analytics: false,
          ccpa: { DoNotShare: true }
      };
      await saveConsentState(rejectNonNecessaryPreferences);
      await updatePreferenceForm(rejectNonNecessaryPreferences);
      await restoreAllowedScripts(rejectNonNecessaryPreferences);
      await _updateObserverState();

      hideBanner(document.getElementById("consent-banner"));
      hideBanner(document.getElementById("initial-consent-banner"));
      hideBanner(document.getElementById("main-banner"));
      hideBanner(document.getElementById("main-consent-banner"));
      hideBanner(document.getElementById("simple-consent-banner"));
    }

    function _isScriptAllowed(categories, normalizedPrefs) {
        if (!Array.isArray(categories) || !normalizedPrefs || Object.keys(normalizedPrefs).length === 0) {
            return false;
        }
        if (categories.includes('necessary')) return true;

        const lowerCasePrefs = Object.fromEntries(
             Object.entries(normalizedPrefs).map(([key, value]) => {
                  if (key.toLowerCase() === 'ccpa' && typeof value === 'object' && value !== null) {
                      return [key.toLowerCase(), { donotshare: value.DoNotShare ?? value.donotshare ?? false }];
                  }
                  return [key.toLowerCase(), value];
             })
        );

        if (lowerCasePrefs.ccpa?.donotshare === true) {
            if (categories.includes('marketing') || categories.includes('personalization') || categories.includes('analytics')) {
                return false;
            }
        }

        const isAllowed = categories.some(cat => lowerCasePrefs[cat.toLowerCase()] === true);
        return isAllowed;
    }

    function _getGtagConsentSettings(normalizedPrefs) {
         const prefs = normalizedPrefs || consentState;
         return {
            'ad_storage': prefs.Marketing ? 'granted' : 'denied',
            'analytics_storage': prefs.Analytics ? 'granted' : 'denied',
            'personalization_storage': prefs.Personalization ? 'granted' : 'denied',
            'functionality_storage': 'granted',
            'security_storage': 'granted',
            'ad_user_data': prefs.Marketing ? 'granted' : 'denied',
            'ad_personalization': prefs.Marketing ? 'granted' : 'denied'
        };
    }
    function _handleGtagConsentUpdate(script, normalizedPrefs) {
        const settings = _getGtagConsentSettings(normalizedPrefs);
        window.dataLayer = window.dataLayer || [];
        window.gtag = window.gtag || function(){dataLayer.push(arguments);};
        gtag('consent', 'update', settings);

        if (script.src && /googletagmanager\.com\/gtag\/js/.test(script.src)) {
             script.onload = () => {
                   window.gtag = window.gtag || function(){dataLayer.push(arguments);};
                   gtag('consent', 'update', settings);
             };
             script.onerror = () => {};
        }
    }
    function _handleAmplitudeConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const analyticsAllowed = prefs.Analytics === true;
        const userProperties = {
            consent_analytics: prefs.Analytics,
            consent_marketing: prefs.Marketing,
            consent_personalization: prefs.Personalization ?? false
        };
        const updateConsent = () => {
            if (typeof amplitude !== "undefined" && amplitude.getInstance) {
                try {
                    const instance = amplitude.getInstance();
                    instance.setOptOut(!analyticsAllowed);
                    instance.setUserProperties(userProperties);
                } catch (error) { }
            } else { }
        };
        if (script.src && /cdn\.(eu\.)?amplitude\.com/.test(script.src)) {
            script.onload = () => { setTimeout(updateConsent, 100); };
            script.onerror = () => { };
        } else { setTimeout(updateConsent, 0); }
    }
    function _handleClarityConsentUpdate(normalizedPrefs) {
         const prefs = normalizedPrefs || consentState;
        window.clarity = window.clarity || function(...args) { (window.clarity.q = window.clarity.q || []).push(args); };
        window.clarity.consent = prefs.Analytics === true;
    }
    function _handleFacebookPixelConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const granted = prefs.Marketing === true;
        window.fbq = window.fbq || function(){fbq.callMethod?fbq.callMethod.apply(fbq,arguments):fbq.queue.push(arguments)};
        window.fbq.queue = window.fbq.queue || [];
        fbq('consent', granted ? 'grant' : 'revoke');
         if (script.src && /connect\.facebook\.net/.test(script.src)) {
              script.onload = () => {
                    window.fbq = window.fbq || function(){fbq.callMethod?fbq.callMethod.apply(fbq,arguments):fbq.queue.push(arguments)};
                    window.fbq.queue = window.fbq.queue || [];
                    fbq('consent', granted ? 'grant' : 'revoke');
              };
              script.onerror = () => { };
         }
    }
    function _handleMatomoConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const granted = prefs.Analytics === true;
        window._paq = window._paq || [];
        if (granted) {
            _paq.push(['setConsentGiven']);
        } else {
            _paq.push(['forgetConsentGiven']);
        }
         if (script.src && /matomo\.cloud/.test(script.src)) {
              script.onload = () => {
                   window._paq = window._paq || [];
                   if(granted) _paq.push(['setConsentGiven']); else _paq.push(['forgetConsentGiven']);
              };
               script.onerror = () => { };
         }
    }
    function _handleHubSpotConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const granted = prefs.Marketing === true || prefs.Personalization === true;
        window._hsq = window._hsq || [];
        _hsq.push(['doNotTrack', !granted]);
        if (script.src && /js\.hs-scripts\.com/.test(script.src)) {
             script.onload = () => {
                  window._hsq = window._hsq || [];
                  _hsq.push(['doNotTrack', !granted]);
             };
             script.onerror = () => { };
        }
    }
    function _handlePlausibleConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const granted = prefs.Analytics === true;
        script.onerror = () => { };
    }
    function _handleHotjarConsentUpdate(script, normalizedPrefs) {
        const prefs = normalizedPrefs || consentState;
        const granted = prefs.Analytics === true;
        window.hj = window.hj || function(...args) { (window.hj.q = window.hj.q || []).push(args); };
        window.hj.q = window.hj.q || [];
        script.onerror = () => { };
    }

    const toolConsentHandlers = [
        { regex: /googletagmanager\.com\/gtag\/js/i, handler: _handleGtagConsentUpdate },
        { regex: /cdn\.(eu\.)?amplitude\.com/i,    handler: _handleAmplitudeConsentUpdate },
        { regex: /clarity\.ms/i,                   handler: _handleClarityConsentUpdate },
        { regex: /connect\.facebook\.net/i,       handler: _handleFacebookPixelConsentUpdate },
        { regex: /matomo\.cloud/i,                 handler: _handleMatomoConsentUpdate },
        { regex: /js\.hs-scripts\.com/i,           handler: _handleHubSpotConsentUpdate },
        { regex: /plausible\.io/i,                handler: _handlePlausibleConsentUpdate },
        { regex: /static\.hotjar\.com/i,          handler: _handleHotjarConsentUpdate }
    ];

    function _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs) {
        if (!scriptInfo?.src) return;
        const src = scriptInfo.src;
        for (const { regex, handler } of toolConsentHandlers) {
            if (regex.test(src)) {
                try {
                    if (handler === _handleClarityConsentUpdate) {
                        handler(normalizedPrefs);
                    } else {
                        handler(script, normalizedPrefs);
                    }
                } catch (toolError) {
                }
                return;
            }
        }
    }

    function _restoreSingleScript(scriptId, scriptInfo, normalizedPrefs) {
        if (!scriptInfo || !scriptInfo.key) {
            if (scriptId && existing_Scripts[scriptId]) delete existing_Scripts[scriptId];
            return;
        }

        const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
        if (!placeholder) {
            delete existing_Scripts[scriptId];
            return;
        }

        const script = document.createElement("script");
        script.type = scriptInfo.type || "text/javascript";
        if (scriptInfo.async) script.async = true;
        if (scriptInfo.defer) script.defer = true;
        const categories = scriptInfo.category || [];
        script.setAttribute("data-category", categories.join(','));

        if (scriptInfo.originalAttributes) {
            Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                script.setAttribute(name, value);
            });
        }

        if (!scriptInfo.src && scriptInfo.content) {
             script.textContent = scriptInfo.content;
        }

        let insertionPoint = placeholder.parentNode;
        let replaced = false;
        if (insertionPoint && document.contains(placeholder)) {
            try {
                insertionPoint.replaceChild(script, placeholder);
                replaced = true;
            } catch (replaceError) {
                 try { document.head.appendChild(script); replaced = true; }
                 catch (appendError) { }
            }
        } else {
             try { document.head.appendChild(script); replaced = true; }
             catch (appendError) { }
        }

        if (replaced) {
            if (scriptInfo.src) {
                script.src = scriptInfo.src;
            }
             _updateToolConsentOnRestore(script, scriptInfo, normalizedPrefs);
        } else {
        }

        delete existing_Scripts[scriptId];
    }

    async function restoreAllowedScripts(preferences) {
        if (observer) {
            observer.disconnect();
        }

        try {
            const currentPrefs = preferences || consentState;
             if (!currentPrefs || Object.keys(currentPrefs).length === 0) {
                return;
            }

             const normalizedPrefs = Object.fromEntries(
                 Object.entries(currentPrefs).map(([key, value]) => {
                     if (key.toLowerCase() === 'ccpa' && typeof value === 'object' && value !== null) {
                         return [key.toLowerCase(), { donotshare: value.DoNotShare ?? value.donotshare ?? false }];
                     }
                     return [key.toLowerCase(), value];
                 })
             );

            const scriptIdsToProcess = Object.keys(existing_Scripts);

            for (const scriptId of scriptIdsToProcess) {
                const scriptInfo = existing_Scripts[scriptId];
                if (!scriptInfo) continue;

                const categories = scriptInfo.category || [];

                if (_isScriptAllowed(categories, normalizedPrefs)) {
                    let alreadyExists = false;
                    if (scriptInfo.src) {
                        const existingExecutableScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain']):not([data-consentbit-id])`);
                        if (existingExecutableScript) {
                            alreadyExists = true;
                            const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
                            if (placeholder?.parentNode) placeholder.parentNode.removeChild(placeholder);
                            delete existing_Scripts[scriptId];
                        }
                    }

                    if (!alreadyExists) {
                        try {
                            _restoreSingleScript(scriptId, scriptInfo, normalizedPrefs);
                        } catch (singleScriptError) {
                        }
                    }
                } else {
                     const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
                     if (!placeholder) {
                          delete existing_Scripts[scriptId];
                     }
                }
            }

        } catch (error) {
        } finally {
            await _updateObserverState();
        }
    }

    async function getVisitorSessionToken() {
      try {
          const existingToken = localStorage.getItem('visitorSessionToken');
          if (existingToken && !isTokenExpired(existingToken)) {
              return existingToken;
          }
          const visitorId = await getOrCreateVisitorId();
          const siteName = await cleanHostname(window.location.hostname);

          const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ visitorId, userAgent: navigator.userAgent, siteName })
          });

          if (!response.ok) {
              const errorText = await response.text();
              throw new Error(`Failed to get visitor session token (${response.status}): ${errorText}`);
          }

          const data = await response.json();
          localStorage.setItem('visitorSessionToken', data.token);
          return data.token;
      } catch (error) {
          return null;
      }
    }

    async function loadConsentStyles() {
      try {
          const cssUrls = [
              "https://cdn.jsdelivr.net/gh/snm62/consentbit@d6b0288/consentbitstyle.css",
              "https://cdn.jsdelivr.net/gh/snm62/consentbit@8c69a0b/consentbit.css"
          ];
          cssUrls.forEach(url => {
              const link = document.createElement("link");
              link.rel = "stylesheet";
              link.href = url;
              link.type = "text/css";
              link.onerror = () => { };
              link.onload = () => { };
              document.head.appendChild(link);
          });
      } catch (error) {
      }
    }

    async function initializeConsentManagement() {
        if (isInitialized) {
             return;
        }
        isInitialized = true;
        isLoadingState = true;

        try {
            const token = await getVisitorSessionToken();
             if (!token) {
                 isLoadingState = false;
                 isInitialized = false;
                 return;
             }

            await loadConsentStyles();
            const decryptedPreferences = await _getDecryptedPreferences();
            consentState = decryptedPreferences || {};

            if (decryptedPreferences) {
                currentBannerType = decryptedPreferences.bannerType || null;
                country = decryptedPreferences.consentCountry || null;
                await updatePreferenceForm(decryptedPreferences);
                await restoreAllowedScripts(decryptedPreferences);

            } else {
                await initializeBannerVisibility();
                initializeBanner();

                if (currentBannerType === 'GDPR') {
                    initialBlockingEnabled = true;
                    await scanAndBlockScripts();
                    const consentBanner = document.getElementById("consent-banner");
                    if (consentBanner) showBanner(consentBanner); else { }

                } else if (currentBannerType === 'CCPA') {
                    initialBlockingEnabled = false;
                    await _updateObserverState();
                    const ccpaBanner = document.getElementById("initial-consent-banner");
                     if (ccpaBanner) showBanner(ccpaBanner); else { }

                } else {
                     initialBlockingEnabled = true;
                     await scanAndBlockScripts();
                     const consentBanner = document.getElementById("consent-banner");
                     if (consentBanner) showBanner(consentBanner); else { }
                }
            }
        } catch (error) {
            initialBlockingEnabled = false;
            await _updateObserverState();
        } finally {
            isLoadingState = false;
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeConsentManagement);
    } else {
        setTimeout(initializeConsentManagement, 0);
    }

    window.consentBit = {
        acceptAllCookies: acceptAllCookies,
        blockAllCookies: blockAllCookies,
        toggleConsentUi: handleToggleConsent
    };

})();

(async function () {
    // Banner Management Functions
    function initializeBanner() {
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

    // Make banner functions globally available
    window.showBanner = showBanner;
    window.hideBanner = hideBanner;
    window.initializeBanner = initializeBanner;

    // Core state management
    const state = {
        existing_Scripts: new Set(),
        blockedScripts: new Map(),
        isLoadingState: false,
        consentState: {},
        observer: null,
        isInitialized: false,
        initialBlockingEnabled: true,
        currentBannerType: null,
        country: null,
        categorizedScripts: null
    };

    // Enhanced analytics patterns
    const analyticsPatterns = [
        {
            name: 'Google Analytics',
            patterns: [
                /googletagmanager\.com\/gtag\/js/i,
                /gtag\('js'/i,
                /gtag\('config'/i,
                /window\.dataLayer/i
            ],
            category: 'Analytics',
            setup: (script) => ({
                type: 'gtag',
                id: script.src?.match(/[?&]id=([^&]+)/)?.[1] || 
                     script.textContent?.match(/gtag\('config',\s*['"]([^'"]+)['"]/)?.[1]
            })
        },
        {
            name: 'Plausible',
            patterns: [
                /plausible\.io\/js\/script\.js/i,
                /data-domain=/i
            ],
            category: 'Analytics',
            setup: (script) => ({
                type: 'plausible',
                domain: script.getAttribute('data-domain')
            })
        },
        {
            name: 'Hotjar',
            patterns: [
                /static\.hj\.contentsquare\.net/i,
                /hj\(|hj\.q/i,
                /_hjSettings/i
            ],
            category: 'Analytics',
            setup: (script) => ({
                type: 'hotjar',
                id: script.textContent?.match(/hjid:\s*(\d+)/)?.[1]
            })
        },
        {
            name: 'Microsoft Clarity',
            patterns: [
                /clarity\.ms\/tag/i,
                /clarity/i
            ],
            category: 'Analytics',
            setup: (script) => ({
                type: 'clarity',
                id: script.src?.match(/clarity\/([^/]+)/)?.[1] ||
                     script.textContent?.match(/clarity",\s*"script",\s*"([^"]+)"/)?.[1]
            })
        },
        {
            name: 'Matomo',
            patterns: [
                /matomo\.cloud/i,
                /matomo\.js/i,
                /_paq/i
            ],
            category: 'Analytics',
            setup: (script) => ({
                type: 'matomo',
                url: script.textContent?.match(/var\s+u="([^"]+)"/)?.[1],
                siteId: script.textContent?.match(/setSiteId',\s*'(\d+)'/)?.[1]
            })
        },
        {
            name: 'HubSpot',
            patterns: [
                /hs-scripts\.com/i,
                /hs-script-loader/i
            ],
            category: 'Marketing',
            setup: (script) => ({
                type: 'hubspot',
                id: script.src?.match(/\/(\d+)\.js/)?.[1]
            })
        }
    ];

    // Enhanced verification system
    const ScriptVerification = {
        blockedScripts: new Set(),
        restoredScripts: new Set(),
        networkBlocked: new Set(),
        errors: new Map(),

        logBlockedScript(script, category) {
            const identifier = script.src || `inline-${this.hashContent(script.textContent)}`;
            this.blockedScripts.add({
                id: identifier,
                category,
                timestamp: Date.now()
            });
            console.log(`🚫 Blocked: ${identifier} (${category})`);
        },

        logRestoredScript(script, category) {
            const identifier = script.src || `inline-${this.hashContent(script.textContent)}`;
            this.restoredScripts.add({
                id: identifier,
                category,
                timestamp: Date.now()
            });
            console.log(`✅ Restored: ${identifier} (${category})`);
        },

        logError(context, error) {
            const errorKey = `${context}-${Date.now()}`;
            this.errors.set(errorKey, {
                context,
                error: error.message,
                stack: error.stack,
                timestamp: Date.now()
            });
            console.error(`❌ Error in ${context}:`, error);
        },

        hashContent(content) {
            if (!content) return 'empty';
            let hash = 0;
            for (let i = 0; i < content.length; i++) {
                hash = ((hash << 5) - hash) + content.charCodeAt(i);
                hash = hash & hash;
            }
            return Math.abs(hash).toString(16);
        },

        getStats() {
            return {
                totalBlocked: this.blockedScripts.size,
                totalRestored: this.restoredScripts.size,
                totalNetworkBlocked: this.networkBlocked.size,
                totalErrors: this.errors.size,
                blockedList: Array.from(this.blockedScripts),
                restoredList: Array.from(this.restoredScripts),
                networkBlockedList: Array.from(this.networkBlocked),
                errors: Array.from(this.errors.values())
            };
        },

        reset() {
            this.blockedScripts.clear();
            this.restoredScripts.clear();
            this.networkBlocked.clear();
            this.errors.clear();
        },

        detectAnalyticsTool(script) {
            for (const tool of analyticsPatterns) {
                if (tool.patterns.some(pattern => 
                    pattern.test(script.src || '') || 
                    pattern.test(script.textContent || '')
                )) {
                    return {
                        name: tool.name,
                        category: tool.category,
                        details: tool.setup(script)
                    };
                }
            }
            return null;
        }
    };

    // Enhanced script management
    const ScriptManager = {
        async createScriptElement(originalScript, isPlaceholder = false) {
            const script = document.createElement('script');
            
            try {
                // Copy all original attributes
                Array.from(originalScript.attributes).forEach(attr => {
                    if (!['src', 'type'].includes(attr.name)) {
                        script.setAttribute(attr.name, attr.value);
                    }
                });

                if (isPlaceholder) {
                    script.type = 'text/plain';
                    if (originalScript.src) {
                        script.setAttribute('data-original-src', originalScript.src);
                    }
                } else {
                    if (originalScript.hasAttribute('data-original-src')) {
                        script.src = originalScript.getAttribute('data-original-src');
                    } else if (originalScript.src) {
                        script.src = originalScript.src;
                    }
                    script.type = 'text/javascript';
                }

                // Handle inline scripts
                if (!script.src && originalScript.textContent) {
                    script.textContent = originalScript.textContent;
                }

                return script;
            } catch (error) {
                ScriptVerification.logError('createScriptElement', error);
                return null;
            }
        },

        async loadScript(script) {
            return new Promise((resolve, reject) => {
                if (!script.src) {
                    resolve(script);
                    return;
                }

                script.onload = () => resolve(script);
                script.onerror = (error) => {
                    ScriptVerification.logError('loadScript', error);
                    reject(error);
                };
            });
        },

        async handleAnalyticsScript(script, analyticsInfo) {
            const placeholder = document.createElement('script');
            placeholder.type = 'text/plain';
            placeholder.setAttribute('data-category', analyticsInfo.category);
            placeholder.setAttribute('data-analytics-type', analyticsInfo.name);
            
            if (script.src) {
                placeholder.setAttribute('data-original-src', script.src);
            }
            
            // Store additional analytics details
            if (analyticsInfo.details) {
                placeholder.setAttribute('data-analytics-details', 
                    JSON.stringify(analyticsInfo.details));
            }

            // Copy other attributes
            Array.from(script.attributes).forEach(attr => {
                if (!['src', 'type'].includes(attr.name)) {
                    placeholder.setAttribute(attr.name, attr.value);
                }
            });

            return placeholder;
        }
    };

    // Enhanced ConsentManager with EncryptionUtils
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
            return await crypto.subtle.importKey(
                'raw',
                rawKey,
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
            return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
        },

        async decrypt(encryptedData, key, iv) {
            const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encryptedBytes
            );
            return new TextDecoder().decode(decrypted);
        }
    };

    const ConsentManager = {
        async saveConsent(preferences) {
            try {
                const encryptedData = await this.encryptPreferences(preferences);
                localStorage.setItem('consent-preferences', JSON.stringify(encryptedData));
                localStorage.setItem('consent-given', 'true');
                return true;
            } catch (error) {
                ScriptVerification.logError('saveConsent', error);
                return false;
            }
        },

        async loadConsent() {
            try {
                const savedData = localStorage.getItem('consent-preferences');
                if (!savedData) return null;

                const encryptedData = JSON.parse(savedData);
                return await this.decryptPreferences(encryptedData);
            } catch (error) {
                ScriptVerification.logError('loadConsent', error);
                return null;
            }
        },

        async encryptPreferences(preferences) {
            try {
                // Generate key and IV using EncryptionUtils
                const { key, iv } = await EncryptionUtils.generateKey();

                // Convert preferences to string with metadata
                const preferencesString = JSON.stringify({
                    ...preferences,
                    timestamp: Date.now(),
                    version: '1.0'
                });

                // Encrypt using EncryptionUtils
                const encryptedData = await EncryptionUtils.encrypt(preferencesString, key, iv);

                // Export the key for storage
                const exportedKey = await crypto.subtle.exportKey('raw', key);

                // Return encrypted data with key and IV
                return {
                    encryptedData,
                    key: Array.from(new Uint8Array(exportedKey)),
                    iv: Array.from(iv),
                    timestamp: Date.now()
                };
            } catch (error) {
                console.error('Error encrypting preferences:', error);
                throw error;
            }
        },

        async decryptPreferences(encryptedData) {
            try {
                // Import the key using EncryptionUtils
                const key = await EncryptionUtils.importKey(
                    new Uint8Array(encryptedData.key),
                    ['decrypt']
                );

                // Decrypt using EncryptionUtils
                const decryptedText = await EncryptionUtils.decrypt(
                    encryptedData.encryptedData,
                    key,
                    new Uint8Array(encryptedData.iv)
                );

                // Parse and validate the decrypted data
                const preferences = JSON.parse(decryptedText);
                if (!this.validatePreferences(preferences)) {
                    throw new Error('Invalid preferences format');
                }

                return preferences;
            } catch (error) {
                console.error('Error decrypting preferences:', error);
                throw error;
            }
        },

        validatePreferences(preferences) {
            const requiredKeys = ['Necessary', 'Marketing', 'Personalization', 'Analytics'];
            return requiredKeys.every(key => typeof preferences[key] === 'boolean');
        },

        // Helper function to check if stored preferences are valid
        async validateStoredPreferences() {
            try {
                const preferences = await this.loadConsent();
                if (!preferences) return false;
                
                const isValid = this.validatePreferences(preferences);
                if (!isValid) {
                    console.warn('Invalid stored preferences found, clearing...');
                    localStorage.removeItem('consent-preferences');
                    localStorage.removeItem('consent-given');
                }
                return isValid;
            } catch (error) {
                console.error('Error validating stored preferences:', error);
                return false;
            }
        }
    };

    // Analytics Consent Handlers
    const AnalyticsConsentHandlers = {
        async updateGoogleAnalytics(preferences) {
            try {
                if (typeof gtag === "function") {
                    console.log("📝 Updating Google Analytics consent settings...");
                    await gtag('consent', 'update', {
                        'ad_storage': preferences.Marketing ? 'granted' : 'denied',
                        'analytics_storage': preferences.Analytics ? 'granted' : 'denied',
                        'ad_personalization': preferences.Marketing ? 'granted' : 'denied',
                        'ad_user_data': preferences.Marketing ? 'granted' : 'denied',
                        'personalization_storage': preferences.Personalization ? 'granted' : 'denied'
                    });
                    
                    // Verify the update
                    await ConsentVerification.verifyGoogleAnalytics();
                    console.log("✅ GA consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating GA consent:", error);
            }
        },

        async updatePlausible(preferences) {
            try {
                if (window.plausible) {
                    console.log("📝 Updating Plausible consent settings...");
                    window.plausible.enableAutoTracking = preferences.Analytics;
                    if (!preferences.Analytics) {
                        window.plausible.pause();
                    } else {
                        window.plausible.resume();
                    }
                    
                    // Verify the update
                    await ConsentVerification.verifyPlausible();
                    console.log("✅ Plausible consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating Plausible consent:", error);
            }
        },

        async updateHotjar(preferences) {
            try {
                if (window.hj) {
                    console.log("📝 Updating Hotjar consent settings...");
                    if (!preferences.Analytics) {
                        window._hjSettings = window._hjSettings || {};
                        window._hjSettings.consent = false;
                        window.hj('consent', 'no');
                    } else {
                        window._hjSettings = window._hjSettings || {};
                        window._hjSettings.consent = true;
                        window.hj('consent', 'yes');
                    }
                    
                    // Verify the update
                    await ConsentVerification.verifyHotjar();
                    console.log("✅ Hotjar consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating Hotjar consent:", error);
            }
        },

        async updateClarity(preferences) {
            try {
                if (window.clarity) {
                    console.log("📝 Updating Clarity consent settings...");
                    if (!preferences.Analytics) {
                        window.clarity('consent', false);
                        window.clarity('stop');
                    } else {
                        window.clarity('consent', true);
                        window.clarity('start');
                    }
                    
                    // Verify the update
                    await ConsentVerification.verifyClarity();
                    console.log("✅ Clarity consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating Clarity consent:", error);
            }
        },

        async updateMatomo(preferences) {
            try {
                if (window._paq) {
                    console.log("📝 Updating Matomo consent settings...");
                    if (!preferences.Analytics) {
                        window._paq.push(['forgetConsentGiven']);
                        window._paq.push(['optUserOut']);
                    } else {
                        window._paq.push(['setConsentGiven']);
                        window._paq.push(['forgetUserOptOut']);
                    }
                    
                    // Verify the update
                    await ConsentVerification.verifyMatomo();
                    console.log("✅ Matomo consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating Matomo consent:", error);
            }
        },

        async updateHubSpot(preferences) {
            try {
                if (window.hubspot) {
                    console.log("📝 Updating HubSpot consent settings...");
                    window._hsq = window._hsq || [];
                    window._hsq.push(['setPrivacyConsent', {
                        analytics: preferences.Analytics,
                        marketing: preferences.Marketing,
                        personalization: preferences.Personalization
                    }]);
                    
                    // Verify the update
                    await ConsentVerification.verifyHubSpot();
                    console.log("✅ HubSpot consent updated successfully");
                }
            } catch (error) {
                console.error("❌ Error updating HubSpot consent:", error);
            }
        }
    };

    // Enhanced script blocking and restoration
    async function scanAndBlockScripts() {
        console.log("=== Starting Enhanced Script Scan ===");
        ScriptVerification.reset();

        try {
            const scripts = document.querySelectorAll("script");
            const categorizedScripts = await loadCategorizedScripts();

            console.log(`Found ${scripts.length} scripts to process`);

            for (const script of scripts) {
                try {
                    // First check for known analytics tools
                    const analyticsInfo = ScriptVerification.detectAnalyticsTool(script);
                    if (analyticsInfo) {
                        const placeholder = await ScriptManager.handleAnalyticsScript(
                            script, 
                            analyticsInfo
                        );
                        if (placeholder) {
                            script.parentNode.replaceChild(placeholder, script);
                            state.existing_Scripts.add(placeholder);
                            ScriptVerification.logBlockedScript(script, analyticsInfo.category);
                            continue;
                        }
                    }

                    // Fall back to general categorization
                    const category = await categorizeScript(script, categorizedScripts);
                    if (category) {
                        const placeholder = await ScriptManager.createScriptElement(script, true);
                        if (placeholder) {
                            placeholder.setAttribute('data-category', category);
                            script.parentNode.replaceChild(placeholder, script);
                            state.existing_Scripts.add(placeholder);
                            ScriptVerification.logBlockedScript(script, category);
                        }
                    }
                } catch (error) {
                    ScriptVerification.logError('processScript', error);
                }
            }

            setupMutationObserver();
            console.log("=== Script Scan Complete ===");
            console.log("Verification Stats:", ScriptVerification.getStats());
        } catch (error) {
            ScriptVerification.logError('scanAndBlockScripts', error);
        }
    }

    async function restoreAllowedScripts(preferences) {
        console.log("=== Starting Enhanced Script Restoration ===");
        
        try {
            const normalizedPrefs = normalizePreferences(preferences);
            const restorationPromises = Array.from(state.existing_Scripts).map(async (placeholder) => {
                try {
                    const category = placeholder.getAttribute('data-category');
                    if (!category) return;

                    const isAllowed = checkScriptAllowed(category, normalizedPrefs);
                    if (isAllowed) {
                        const analyticsType = placeholder.getAttribute('data-analytics-type');
                        const analyticsDetails = placeholder.getAttribute('data-analytics-details');

                        if (analyticsType && analyticsDetails) {
                            // Handle analytics script restoration
                            await restoreAnalyticsScript(placeholder, JSON.parse(analyticsDetails));
                        } else {
                            // Handle regular script restoration
                            const script = await ScriptManager.createScriptElement(placeholder, false);
                            if (script) {
                                await ScriptManager.loadScript(script);
                                placeholder.parentNode.replaceChild(script, placeholder);
                                ScriptVerification.logRestoredScript(script, category);
                            }
                        }
                    }
                } catch (error) {
                    ScriptVerification.logError('restoreScript', error);
                }
            });

            await Promise.allSettled(restorationPromises);
            console.log("=== Script Restoration Complete ===");
            console.log("Verification Stats:", ScriptVerification.getStats());
        } catch (error) {
            ScriptVerification.logError('restoreAllowedScripts', error);
        }
    }

    async function restoreAnalyticsScript(placeholder, details) {
        const script = document.createElement('script');
        const originalSrc = placeholder.getAttribute('data-original-src');

        if (originalSrc) {
            script.src = originalSrc;
        }

        // Copy attributes
        Array.from(placeholder.attributes).forEach(attr => {
            if (!['type', 'data-original-src', 'data-analytics-type', 'data-analytics-details'].includes(attr.name)) {
                script.setAttribute(attr.name, attr.value);
            }
        });

        // Get current preferences
        const currentPreferences = await ConsentManager.loadConsent() || {
            Necessary: true,
            Marketing: false,
            Analytics: false,
            Personalization: false
        };

        // Special handling for different analytics types
        switch (details.type) {
            case 'gtag':
                if (originalSrc?.includes('googletagmanager.com')) {
                    // This is the GA loader script
                    script.onload = async () => {
                        // Wait for gtag to be available
                        await waitForFunction(() => typeof gtag === 'function');
                        await AnalyticsConsentHandlers.updateGoogleAnalytics(currentPreferences);
                    };
                }
                break;
            case 'plausible':
                script.onload = async () => {
                    await waitForFunction(() => window.plausible);
                    await AnalyticsConsentHandlers.updatePlausible(currentPreferences);
                };
                break;
            case 'hotjar':
                script.onload = async () => {
                    await waitForFunction(() => window.hj);
                    await AnalyticsConsentHandlers.updateHotjar(currentPreferences);
                };
                break;
            case 'clarity':
                script.onload = async () => {
                    await waitForFunction(() => window.clarity);
                    await AnalyticsConsentHandlers.updateClarity(currentPreferences);
                };
                break;
            case 'matomo':
                script.onload = async () => {
                    await waitForFunction(() => window._paq);
                    await AnalyticsConsentHandlers.updateMatomo(currentPreferences);
                };
                break;
            case 'hubspot':
                script.onload = async () => {
                    await waitForFunction(() => window.hubspot);
                    await AnalyticsConsentHandlers.updateHubSpot(currentPreferences);
                };
                break;
        }

        placeholder.parentNode.replaceChild(script, placeholder);
        ScriptVerification.logRestoredScript(script, placeholder.getAttribute('data-category'));
    }

    // Helper functions
    function normalizePreferences(preferences) {
        return Object.fromEntries(
            Object.entries(preferences).map(([key, value]) => [key.toLowerCase(), value])
        );
    }

    function checkScriptAllowed(category, preferences) {
        const categories = category.split(',').map(c => c.trim().toLowerCase());
        return categories.some(cat => preferences[cat] === true);
    }

    async function categorizeScript(script, categorizedScripts) {
        const src = script.src;
        const content = script.textContent;

        // Check against categorized scripts
        const matched = categorizedScripts?.find(s => 
            (src && normalizeUrl(s.src) === normalizeUrl(src)) ||
            (content && s.content?.trim() === content?.trim())
        );

        if (matched?.category) return matched.category;

        // Check against patterns
        return findCategoryByPattern(src || content);
    }

    function setupMutationObserver() {
        if (state.observer) {
            state.observer.disconnect();
        }

        state.observer = new MutationObserver(async (mutations) => {
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    if (node.tagName === 'SCRIPT') {
                        try {
                            const category = await categorizeScript(node, state.categorizedScripts);
                            if (category) {
                                const placeholder = await ScriptManager.createScriptElement(node, true);
                                if (placeholder) {
                                    placeholder.setAttribute('data-category', category);
                                    node.parentNode.replaceChild(placeholder, node);
                                    state.existing_Scripts.add(placeholder);
                                    ScriptVerification.logBlockedScript(node, category);
                                }
                            }
                        } catch (error) {
                            ScriptVerification.logError('mutationObserver', error);
                        }
                    }
                }
            }
        });

        state.observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    }

    // Initialize the system
     async function initialize() {
        console.log("=== Starting System Initialization ===");
        
        try {
            if (state.isInitialized) {
                console.log("System already initialized");
                return;
            }

            // Enable initial blocking
            state.initialBlockingEnabled = true;
            blockAllInitialRequests();

            // First, get visitor session token
            const token = await getVisitorSessionToken();
            if (!token) {
                console.warn("Failed to get visitor session token, proceeding with limited functionality");
            }

            // Then initialize banner visibility based on location
            await initializeBannerVisibility();

            // Load consent styles
            await loadConsentStyles();

            // Initialize banner and attach handlers
            initializeBanner();

            state.isInitialized = true;
            console.log("=== System Initialization Complete ===");

            // Verify initial state
            await ConsentVerification.verifyAllTools();
        } catch (error) {
            ScriptVerification.logError('initialize', error);
            console.error("Failed to initialize system:", error);
            
            // Fallback initialization
            try {
                state.initialBlockingEnabled = true;
                blockAllInitialRequests();
                await initializeBannerVisibility();
                initializeBanner();
            } catch (fallbackError) {
                console.error("Critical: Fallback initialization failed:", fallbackError);
            }
        }
    }

    // Export necessary functions to window
    window.ScriptVerification = ScriptVerification;
    window.ConsentManager = ConsentManager;
    window.initialize = initialize;
    window.scanAndBlockScripts = scanAndBlockScripts;
    window.restoreAllowedScripts = restoreAllowedScripts;
    window.initializeBannerVisibility = initializeBannerVisibility;
    window.showBanner = showBanner;
    window.hideBanner = hideBanner;

    // Start initialization when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

    // Enhanced consent action handlers
    async function handleAcceptAllConsent() {
        console.log("=== Handling Accept All Consent ===");
        try {
            const preferences = {
                Necessary: true,
                Marketing: true,
                Personalization: true,
                Analytics: true,
                DoNotShare: false
            };

            // Save consent state
            await ConsentManager.saveConsent(preferences);
            
            // Restore all scripts
            await restoreAllowedScripts(preferences);
            
            // Hide banners
            hideBanner(document.getElementById("consent-banner"));
            hideBanner(document.getElementById("main-banner"));
            
            console.log("✅ Accept All: Scripts restored successfully");
            console.log("Restored scripts:", ScriptVerification.getStats());
        } catch (error) {
            ScriptVerification.logError('handleAcceptAllConsent', error);
        }
    }

    async function handleRejectAllConsent() {
        console.log("=== Handling Reject All Consent ===");
        try {
            const preferences = {
                Necessary: true,
                Marketing: false,
                Personalization: false,
                Analytics: false,
                DoNotShare: true
            };

            // Save consent state
            await ConsentManager.saveConsent(preferences);
            
            // Block all non-necessary scripts
            await scanAndBlockScripts();
            
            // Hide banners
            hideBanner(document.getElementById("consent-banner"));
            hideBanner(document.getElementById("main-banner"));
            
            console.log("🚫 Reject All: Scripts blocked successfully");
            console.log("Blocked scripts:", ScriptVerification.getStats());
        } catch (error) {
            ScriptVerification.logError('handleRejectAllConsent', error);
        }
    }

    async function handlePreferencesSave(formElement) {
        console.log("=== Handling Preferences Save ===");
        try {
            const preferences = {
                Necessary: true,
                Marketing: formElement.querySelector('[data-consent-id="marketing-checkbox"]')?.checked || false,
                Personalization: formElement.querySelector('[data-consent-id="personalization-checkbox"]')?.checked || false,
                Analytics: formElement.querySelector('[data-consent-id="analytics-checkbox"]')?.checked || false,
                DoNotShare: formElement.querySelector('[data-consent-id="do-not-share-checkbox"]')?.checked || false
            };

            console.log("📝 Selected preferences:", preferences);

            // Save consent state
            await ConsentManager.saveConsent(preferences);
            
            // Update all analytics tools with new preferences
            await Promise.all([
                AnalyticsConsentHandlers.updateGoogleAnalytics(preferences),
                AnalyticsConsentHandlers.updatePlausible(preferences),
                AnalyticsConsentHandlers.updateHotjar(preferences),
                AnalyticsConsentHandlers.updateClarity(preferences),
                AnalyticsConsentHandlers.updateMatomo(preferences),
                AnalyticsConsentHandlers.updateHubSpot(preferences)
            ]);

            // Verify all updates
            console.log("🔍 Verifying consent updates...");
            await ConsentVerification.verifyAllTools();

            // Block all scripts first
            await scanAndBlockScripts();
            
            // Then restore allowed scripts based on preferences
            await restoreAllowedScripts(preferences);
            
            // Hide banners
            hideBanner(document.getElementById("consent-banner"));
            hideBanner(document.getElementById("main-banner"));
            hideBanner(document.getElementById("main-consent-banner"));
            
            console.log("✅ Preferences saved and applied successfully");
            console.log("Current script status:", ScriptVerification.getStats());
        } catch (error) {
            console.error("❌ Error in handlePreferencesSave:", error);
            ScriptVerification.logError('handlePreferencesSave', error);
        }
    }

    async function handleCCPAToggle(isChecked) {
        console.log("=== Handling CCPA Toggle ===");
        try {
            const preferences = {
                Necessary: true,
                Marketing: !isChecked,
                Personalization: !isChecked,
                Analytics: !isChecked,
                DoNotShare: isChecked
            };

            // Save consent state
            await ConsentManager.saveConsent(preferences);
            
            if (isChecked) {
                // If DoNotShare is checked, block all non-necessary scripts
                await scanAndBlockScripts();
                console.log("🚫 CCPA: Scripts blocked due to Do Not Share");
            } else {
                // If DoNotShare is unchecked, restore all scripts
                await restoreAllowedScripts(preferences);
                console.log("✅ CCPA: Scripts restored");
            }
            
            console.log("Current script status:", ScriptVerification.getStats());
        } catch (error) {
            ScriptVerification.logError('handleCCPAToggle', error);
        }
    }

    // Update banner handlers
    function attachBannerHandlers() {
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
    const closeConsentButton = document.getElementById("close-consent-banner");
    const doNotShareLink = document.getElementById("do-not-share-link");
    doNotShareLink? "true":"false";
  
  
      
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
            Necessary: true,
            Marketing: true,
            Personalization: true,
            Analytics: true,
            DoNotShare: false
          };
          
            await saveConsentState(preferences);
             restoreAllowedScripts(preferences);
             hideBanner(simpleBanner);
            localStorage.setItem("consent-given", "true");
          
          });
        }
      
  
      if (simpleRejectButton) {
        simpleRejectButton.addEventListener("click", async function(e) {
          e.preventDefault();
          console.log('Reject button clicked');
          const preferences = {
            Necessary: true,
            Marketing: false,
            Personalization: false,
            Analytics: false,
            DoNotShare: true
          };
          await saveConsentState(preferences);
          checkAndBlockNewScripts();
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
        const acceptButton = document.getElementById("accept-btn");
        if (acceptButton) {
            acceptButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleAcceptAllConsent();
            });
        }

        // Decline button handler
        const declineButton = document.getElementById("decline-btn");
        if (declineButton) {
            declineButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleRejectAllConsent();
            });
        }

        // Save preferences button handler
        const savePreferencesButton = document.getElementById("save-preferences-btn");
        if (savePreferencesButton) {
            savePreferencesButton.addEventListener("click", async function(e) {
                e.preventDefault();
                const form = document.getElementById("main-banner") || 
                            document.getElementById("main-consent-banner");
                await handlePreferencesSave(form);
            });
        }

        // CCPA checkbox handler
        const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
        if (doNotShareCheckbox) {
            doNotShareCheckbox.addEventListener("change", async function(e) {
                await handleCCPAToggle(e.target.checked);
            });
        }

        // Cancel button in preferences
        const cancelButton = document.getElementById("cancel-btn");
        if (cancelButton) {
            cancelButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleRejectAllConsent();
            });
        }
    }

    // Enhanced initialization for different banner types
    async function initializeBannerVisibility() {
        console.log("=== Initializing Banner Visibility ===");
        try {
            const locationData = await detectLocationAndGetBannerType();
            state.currentBannerType = locationData?.bannerType;
            state.country = locationData?.country;

            console.log("Location Data:", {
                bannerType: state.currentBannerType,
                country: state.country
            });

            const consentGiven = localStorage.getItem("consent-given");
            const consentBanner = document.getElementById("consent-banner");
            const ccpaBanner = document.getElementById("initial-consent-banner");
            const mainBanner = document.getElementById("main-banner");
            const mainConsentBanner = document.getElementById("main-consent-banner");

            // Hide all banners initially
            [consentBanner, ccpaBanner, mainBanner, mainConsentBanner].forEach(banner => {
                if (banner) hideBanner(banner);
            });

            if (consentGiven === "true") {
                console.log("Consent already given, loading saved preferences");
                const savedPreferences = await ConsentManager.loadConsent();
                if (savedPreferences) {
                    console.log("Applying saved preferences:", savedPreferences);
                    await restoreAllowedScripts(savedPreferences);
                }
                return;
            }

            // Initial setup based on banner type
            if (state.currentBannerType === "CCPA") {
                console.log("Initializing CCPA banner");
                // For CCPA, start with all scripts unblocked
                const initialPreferences = {
                    Necessary: true,
                    Marketing: true,
                    Personalization: true,
                    Analytics: true,
                    DoNotShare: false
                };
                await restoreAllowedScripts(initialPreferences);
                if (ccpaBanner) showBanner(ccpaBanner);
            } else {
                console.log("Initializing GDPR banner");
                // For GDPR and others, start with all scripts blocked
                await scanAndBlockScripts();
                if (consentBanner) showBanner(consentBanner);
            }

            // Log initialization status
            console.log("Banner initialization complete:", {
                bannerType: state.currentBannerType,
                consentGiven,
                gdprBannerVisible: consentBanner?.style.display !== 'none',
                ccpaBannerVisible: ccpaBanner?.style.display !== 'none'
            });

        } catch (error) {
            ScriptVerification.logError('initializeBannerVisibility', error);
            console.error("Failed to initialize banner visibility:", error);
            
            // Fallback to GDPR banner in case of error
            const consentBanner = document.getElementById("consent-banner");
            if (consentBanner) {
                console.log("Falling back to GDPR banner due to error");
                showBanner(consentBanner);
                await scanAndBlockScripts();
            }
        }
    }

    // Helper function to wait for a function to be available
    function waitForFunction(predicate, timeout = 2000) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const interval = setInterval(() => {
                if (predicate()) {
                    clearInterval(interval);
                    resolve();
                } else if (Date.now() - startTime > timeout) {
                    clearInterval(interval);
                    reject(new Error('Timeout waiting for function'));
                }
            }, 100);
        });
    }

    // Add debug function to window for easy testing
    window.verifyConsent = async () => {
        console.log('=== Manual Consent Verification ===');
        const results = await ConsentVerification.verifyAllTools();
        const currentPreferences = await ConsentManager.loadConsent();
        console.log('Current Preferences:', currentPreferences);
        return { results, preferences: currentPreferences };
    };

    // Add debug function for banner state
    window.checkBannerState = () => {
        const banners = {
            consentBanner: document.getElementById("consent-banner"),
            ccpaBanner: document.getElementById("initial-consent-banner"),
            mainBanner: document.getElementById("main-banner"),
            mainConsentBanner: document.getElementById("main-consent-banner")
        };

        return Object.entries(banners).reduce((state, [name, banner]) => {
            state[name] = banner ? {
                exists: true,
                visible: banner.style.display !== 'none',
                classes: banner.className
            } : {
                exists: false
            };
            return state;
        }, {});
    };

    // Add debug function to check encryption
    window.testConsentEncryption = async () => {
        try {
            const testPreferences = {
                Necessary: true,
                Marketing: false,
                Personalization: true,
                Analytics: false,
                DoNotShare: false
            };

            console.log('Testing consent encryption/decryption...');
            console.log('Original preferences:', testPreferences);

            // Test encryption
            const encrypted = await ConsentManager.encryptPreferences(testPreferences);
            console.log('Encrypted data:', encrypted);

            // Test decryption
            const decrypted = await ConsentManager.decryptPreferences(encrypted);
            console.log('Decrypted preferences:', decrypted);

            // Verify
            const isValid = ConsentManager.validatePreferences(decrypted);
            console.log('Validation result:', isValid);

            return {
                success: true,
                originalPreferences: testPreferences,
                encryptedData: encrypted,
                decryptedPreferences: decrypted,
                isValid
            };
        } catch (error) {
            console.error('Encryption test failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    };


        // Initialization Utilities
        async function getOrCreateVisitorId() {
            let visitorId = localStorage.getItem('visitorId');
            if (!visitorId) {
                visitorId = generateUUID();
                localStorage.setItem('visitorId', visitorId);
            }
            return visitorId;
        }
    
        function generateUUID() {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        }
    
        function cleanHostname(hostname) {
            // Remove www. and get base domain
            return hostname.replace(/^www\./, '').split('.').slice(-2).join('.');
        }
    
        function isTokenExpired(token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                return payload.exp * 1000 < Date.now();
            } catch (error) {
                console.error('Error checking token expiration:', error);
                return true;
            }
        }
    
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
                    console.log("Token is in localstorage");
                    return token;
                }
    
                // Request new token from server
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
                    throw new Error('Failed to get visitor session token');
                }
    
                const data = await response.json();
                
                // Store the new token
                localStorage.setItem('visitorSessionToken', data.token);
                
                return data.token;
            } catch (error) {
                console.error('Error getting visitor session token:', error);
                return null;
            }
        }
    
})();

   
   

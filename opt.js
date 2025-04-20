(async function () {
    // Configuration object
    const CONFIG = {
        STORAGE_KEYS: {
            CONSENT_GIVEN: 'consent-given',
            CONSENT_PREFERENCES: 'consent-preferences',
            VISITOR_ID: 'visitorId',
            VISITOR_TOKEN: 'visitorSessionToken',
            DEBUG_MODE: 'debug-mode',
            POLICY_VERSION: 'consent-policy-version'
        },
        API_ENDPOINTS: {
            VISITOR_TOKEN: 'https://cb-server.web-8fb.workers.dev/api/visitor-token',
            DETECT_LOCATION: 'https://cb-server.web-8fb.workers.dev/api/cmp/detect-location',
            SCRIPT_CATEGORY: 'https://cb-server.web-8fb.workers.dev/api/cmp/script-category',
            CONSENT: 'https://cb-server.web-8fb.workers.dev/api/cmp/consent'
        },
        POLICY_VERSION: '1.2'
    };

    // Utility functions
    const Utils = {
        debugLog: (message, level = 'info') => {
            if (localStorage.getItem(CONFIG.STORAGE_KEYS.DEBUG_MODE) === 'true') {
                console[level](`[ConsentBit] ${message}`);
            }
        },
        
        generateUUID: () => {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        },

        isValidJSON: (str) => {
            try {
                JSON.parse(str);
                return true;
            } catch (e) {
                return false;
            }
        }
    };

    // Add initialization guard
    let isInitializing = false;

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

    // Request Blocking Helper
    function isSuspiciousResource(url) {
        if (!url) return false;
        
        const suspiciousPatterns = [
            /google-analytics/,
            /googletagmanager/,
            /facebook\.com/,
            /doubleclick\.net/,
            /analytics/,
            /tracking/,
            /clarity\.ms/,
            /hotjar/,
            /plausible/
            // Add more patterns as needed
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(url));
    }

    // Placeholder for ConsentVerification
    const ConsentVerification = {
        verifyGoogleAnalytics: async () => console.log("Placeholder: verifyGoogleAnalytics called"),
        verifyPlausible: async () => console.log("Placeholder: verifyPlausible called"),
        verifyHotjar: async () => console.log("Placeholder: verifyHotjar called"),
        verifyClarity: async () => console.log("Placeholder: verifyClarity called"),
        verifyMatomo: async () => console.log("Placeholder: verifyMatomo called"),
        verifyHubSpot: async () => console.log("Placeholder: verifyHubSpot called"),
        verifyAllTools: async () => console.log("Placeholder: verifyAllTools called"),
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

    // Enhanced ConsentManager with proper consent handling
    class ConsentManager {
        constructor() {
            this.preferences = this.loadPreferences();
            this.consentGiven = this.hasConsentBeenGiven();
            this.initializeAnalyticsBlocking();
        }

        initializeAnalyticsBlocking() {
            if (!this.consentGiven) {
                blockAllInitialRequests();
            }
        }

        loadPreferences() {
            const stored = localStorage.getItem(CONFIG.STORAGE_KEYS.CONSENT_PREFERENCES);
            return Utils.isValidJSON(stored) ? JSON.parse(stored) : {
                Necessary: true,
                Marketing: false,
                Personalization: false,
                Analytics: false,
                DoNotShare: false
            };
        }

        hasConsentBeenGiven() {
            return localStorage.getItem(CONFIG.STORAGE_KEYS.CONSENT_GIVEN) === 'true';
        }

        async savePreferences(preferences) {
            try {
                console.log('Saving consent preferences:', preferences);
                
                // Save preferences to storage
                localStorage.setItem(CONFIG.STORAGE_KEYS.CONSENT_PREFERENCES, JSON.stringify(preferences));
                localStorage.setItem(CONFIG.STORAGE_KEYS.CONSENT_GIVEN, 'true');
                localStorage.setItem(CONFIG.STORAGE_KEYS.POLICY_VERSION, CONFIG.POLICY_VERSION);
                
                this.preferences = preferences;
                this.consentGiven = true;

                // If consent is accepted, unblock and restore scripts
                if (preferences.Analytics || preferences.Marketing || preferences.Personalization) {
                    console.log('Consent accepted, restoring scripts...');
                    state.initialBlockingEnabled = false;
                    await this.restoreAnalytics(preferences);
                } else {
                    console.log('Consent rejected, maintaining blocks...');
                    state.initialBlockingEnabled = true;
                    await this.blockAnalytics();
                }

                // Update analytics tools with new preferences
                await Promise.all([
                    AnalyticsConsentHandlers.updateGoogleAnalytics(preferences),
                    AnalyticsConsentHandlers.updatePlausible(preferences),
                    AnalyticsConsentHandlers.updateHotjar(preferences),
                    AnalyticsConsentHandlers.updateClarity(preferences),
                    AnalyticsConsentHandlers.updateMatomo(preferences),
                    AnalyticsConsentHandlers.updateHubSpot(preferences)
                ]);

                console.log('Consent preferences saved and applied successfully');
                return true;
            } catch (error) {
                console.error('Error saving consent preferences:', error);
                return false;
            }
        }

        async restoreAnalytics(preferences) {
            if (preferences.Analytics) {
                // Restore analytics objects to their original state
                delete window.gtag;
                delete window.ga;
                delete window.dataLayer;
                delete window.plausible;
                delete window._paq;
                delete window.clarity;
                
                // Restore any blocked scripts
                await restoreAllowedScripts(preferences);
            }
        }

        async blockAnalytics() {
            // Re-enable blocking
            state.initialBlockingEnabled = true;
            blockAllInitialRequests();
            await scanAndBlockScripts();
        }

        getPreferences() {
            return this.preferences;
        }

        isConsentGiven() {
            return this.consentGiven;
        }
    }

    // Enhanced BannerManager with proper method exposure
    class BannerManager {
        constructor() {
            // Initialize banner elements
            this.banners = {
                main: document.getElementById('consent-banner'),
                ccpa: document.getElementById('initial-consent-banner'),
                preferences: document.getElementById('main-banner'),
                simple: document.getElementById('simple-consent-banner')
            };
            this.consentManager = new ConsentManager();
            
            // Bind methods to instance
            this.hideAll = this.hideAll.bind(this);
            this.show = this.show.bind(this);
            this.initialize = this.initialize.bind(this);
        }

        hideAll() {
            console.log('Hiding all banners');
            Object.values(this.banners).forEach(banner => {
                if (banner) {
                    banner.style.display = 'none';
                    banner.classList.remove('show-banner');
                    banner.classList.add('hidden');
                }
            });
        }

        show(bannerType) {
            console.log('Showing banner:', bannerType);
            const banner = this.banners[bannerType];
            if (banner) {
                banner.style.display = 'block';
                banner.classList.add('show-banner');
                banner.classList.remove('hidden');
                banner.style.visibility = 'visible';
                banner.style.opacity = '1';
            } else {
                console.warn(`Banner type ${bannerType} not found`);
            }
        }

        async initialize() {
            try {
                console.log('Initializing BannerManager');
                
                if (this.consentManager.isConsentGiven()) {
                    console.log('Consent already given, applying preferences');
                    await this.consentManager.applyPreferences();
                    return;
                }

                // Default to GDPR banner type
                this.bannerType = 'gdpr';

                try {
                    // Try to get location-based banner type
                    const token = await getVisitorSessionToken();
                    if (token) {
                        const detectedType = await detectLocationAndGetBannerType();
                        if (detectedType) {
                            this.bannerType = detectedType;
                        }
                    }
                } catch (error) {
                    console.warn('Failed to detect location, using default banner type:', error);
                }

                // Hide all banners first
                this.hideAll();

                // Show appropriate banner
                if (this.bannerType === 'ccpa') {
                    this.show('ccpa');
                } else {
                    this.show('main');
                }

                // Attach event listeners
                this.attachEventListeners();
            } catch (error) {
                console.error('Error in BannerManager initialization:', error);
                // Fallback to main banner
                this.show('main');
            }
        }

        attachEventListeners() {
            // Accept all button
            const acceptAllBtn = this.banners.main.querySelector('[data-consent="accept-all"]');
            if (acceptAllBtn) {
                acceptAllBtn.addEventListener('click', () => this.handleAcceptAll());
            }

            // Reject all button
            const rejectAllBtn = this.banners.main.querySelector('[data-consent="reject-all"]');
            if (rejectAllBtn) {
                rejectAllBtn.addEventListener('click', () => this.handleRejectAll());
            }

            // Settings button
            const settingsBtn = this.banners.main.querySelector('[data-consent="settings"]');
            if (settingsBtn) {
                settingsBtn.addEventListener('click', () => this.showSettings());
            }

            // Save preferences button in settings
            if (this.settingsElement) {
                const saveBtn = this.settingsElement.querySelector('[data-consent="save"]');
                if (saveBtn) {
                    saveBtn.addEventListener('click', () => this.handleSavePreferences());
                }
            }
        }

        async handleAcceptAll() {
            console.log('Handling accept all consent...');
            const preferences = {
                Necessary: true,
                Marketing: true,
                Personalization: true,
                Analytics: true,
                DoNotShare: false
            };
            
            // Save and apply preferences
            const success = await this.consentManager.savePreferences(preferences);
            
            if (success) {
                console.log('Accept all consent saved successfully');
                // Hide the banner after successful save
                this.hideAll();
                
                // Trigger any additional callbacks
                if (window.dataLayer && !state.initialBlockingEnabled) {
                    window.dataLayer.push({
                        event: 'consent_accepted',
                        consent_preferences: preferences
                    });
                }
            } else {
                console.error('Failed to save accept all consent');
            }
        }

        async handleRejectAll() {
            console.log('Handling reject all consent...');
            const preferences = {
                Necessary: true,
                Marketing: false,
                Personalization: false,
                Analytics: false,
                DoNotShare: true
            };
            
            // Save and apply preferences
            const success = await this.consentManager.savePreferences(preferences);
            
            if (success) {
                console.log('Reject all consent saved successfully');
                // Hide the banner after successful save
                this.hideAll();
                
                // Trigger any additional callbacks
                if (window.dataLayer && !state.initialBlockingEnabled) {
                    window.dataLayer.push({
                        event: 'consent_rejected',
                        consent_preferences: preferences
                    });
                }
            } else {
                console.error('Failed to save reject all consent');
            }
        }

        async handleSavePreferences() {
            console.log('Handling save preferences...');
            const preferences = {
                Necessary: true,
                Marketing: this.getCheckboxValue('marketing'),
                Personalization: this.getCheckboxValue('personalization'),
                Analytics: this.getCheckboxValue('analytics'),
                DoNotShare: this.getCheckboxValue('do-not-share')
            };
            
            // Save and apply preferences
            const success = await this.consentManager.savePreferences(preferences);
            
            if (success) {
                console.log('Preferences saved successfully');
                this.hideSettings();
                this.hideAll();
                
                // Trigger any additional callbacks
                if (window.dataLayer && !state.initialBlockingEnabled) {
                    window.dataLayer.push({
                        event: 'consent_updated',
                        consent_preferences: preferences
                    });
                }
            } else {
                console.error('Failed to save preferences');
            }
        }

        getCheckboxValue(category) {
            if (!this.settingsElement) return false;
            const checkbox = this.settingsElement.querySelector(`[data-category="${category}"]`);
            return checkbox ? checkbox.checked : false;
        }

        showSettings() {
            if (this.settingsElement) {
                this.settingsElement.classList.remove('hidden');
                this.settingsElement.classList.add('visible');
            }
        }

        hideSettings() {
            if (this.settingsElement) {
                this.settingsElement.classList.remove('visible');
                this.settingsElement.classList.add('hidden');
            }
        }
    }

    // Location detection and banner type determination
    async function detectLocationAndGetBannerType() {
        try {
            const token = localStorage.getItem('visitorSessionToken');
            const response = await fetch(CONFIG.API_ENDPOINTS.DETECT_LOCATION, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to detect location');
            }

            const data = await response.json();
            
            if (!data || !data.region) {
                console.warn('Location detection failed, defaulting to GDPR banner');
                return 'gdpr';
            }

            const regionMap = {
                'EU': 'gdpr',
                'US-CA': 'ccpa',
                'US-VA': 'vcdpa',
                'US-CO': 'cpra',
                'US-CT': 'ctdpa'
            };

            return regionMap[data.region] || 'gdpr';
        } catch (error) {
            console.error('Error detecting location:', error);
            return 'gdpr';
        }
    }

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

    // Placeholder: loadCategorizedScripts
    async function loadCategorizedScripts() {
        console.log("Placeholder: loadCategorizedScripts called");
        // Return an empty array or mock data if needed for testing
        return []; 
    }

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

    // Placeholder: loadConsentStyles
    async function loadConsentStyles() {
        console.log("Placeholder: loadConsentStyles called");
        // Simulate loading styles if necessary
        return Promise.resolve();
    }

    // Update initialization function
    async function initialize() {
        if (isInitializing || state.isInitialized) {
            console.log("Initialization already in progress or completed");
            return;
        }

        isInitializing = true;
        console.log("=== Starting System Initialization ===");
        
        try {
            // Enable initial blocking first
            state.initialBlockingEnabled = true;
            blockAllInitialRequests();

            // Create and expose BannerManager instance
            const bannerManager = new BannerManager();
            Object.defineProperty(window, 'bannerManager', {
                value: bannerManager,
                writable: false,
                configurable: false
            });

            // Initialize banner manager
            await bannerManager.initialize();

            state.isInitialized = true;
            console.log("=== System Initialization Complete ===");
        } catch (error) {
            console.error("Failed to initialize system:", error);
            
            // Fallback initialization
            try {
                if (!window.bannerManager) {
                    const bannerManager = new BannerManager();
                    Object.defineProperty(window, 'bannerManager', {
                        value: bannerManager,
                        writable: false,
                        configurable: false
                    });
                }
                window.bannerManager.show('main');
            } catch (fallbackError) {
                console.error("Critical: Fallback initialization failed:", fallbackError);
            }
        } finally {
            isInitializing = false;
        }
    }

    // Placeholder: saveConsentState
    async function saveConsentState(preferences) {
        console.log("Placeholder: saveConsentState called with:", preferences);
        // Mock saving if needed
        localStorage.setItem("consent-given", "true"); // Mimic original behavior
        return Promise.resolve();
    }
    
    // Placeholder: checkAndBlockNewScripts
    async function checkAndBlockNewScripts() {
        console.log("Placeholder: checkAndBlockNewScripts called");
        return Promise.resolve();
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
            
            // Hide banners using BannerManager
            window.bannerManager.hideAll();
            
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
            
            // Hide banners using BannerManager
            window.bannerManager.hideAll();
            
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
            
            // Hide all banners using BannerManager
            window.bannerManager.hideAll();
            
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

    // Update banner handlers to use BannerManager instance
    function attachBannerHandlers(bannerManager) {
        if (!bannerManager) {
            console.error("BannerManager instance not provided to attachBannerHandlers");
            return;
        }

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
        
        if (doNotShareLink) {
            doNotShareLink.setAttribute("data-consent-given", localStorage.getItem("consent-given") === "true");
        }
      
        // Initialize banner visibility based on user location
        initializeBannerVisibility();
      
        if (simpleBanner) {
            console.log('Simple banner found, initializing handlers');
            bannerManager.show('simple');
        
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
                    bannerManager.hide('simple');
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
                    bannerManager.hide('simple');
                    localStorage.setItem("consent-given", "true");
                });
            }
        }
        
        if (toggleConsentButton) {
            toggleConsentButton.addEventListener("click", async function(e) {
                e.preventDefault();

                if (currentBannerType === 'GDPR') {
                    bannerManager.show('main');
                    bannerManager.hide('ccpa');
                } else if (currentBannerType === 'CCPA') {
                    bannerManager.show('ccpa');
                    bannerManager.hide('main');
                } else {
                    bannerManager.show('main');
                    bannerManager.hide('ccpa');
                }
            });
        }
        
        if (newToggleConsentButton) {
            newToggleConsentButton.addEventListener("click", async function(e) {
                e.preventDefault();
            
                if (currentBannerType === 'GDPR') {
                    bannerManager.show('main');
                    bannerManager.hide('ccpa');
                } else if (currentBannerType === 'CCPA') {
                    bannerManager.show('ccpa');
                    bannerManager.hide('main');
                } else {
                    bannerManager.show('main');
                    bannerManager.hide('ccpa');
                }
            });
        }
        
        if (doNotShareLink) {
            doNotShareLink.addEventListener("click", function(e) {
                e.preventDefault();
                bannerManager.hide('ccpa');
                bannerManager.show('preferences');
            });
        }
        
        if (closeConsentButton) {
            closeConsentButton.addEventListener("click", function(e) {
                e.preventDefault();
                bannerManager.hide('preferences');
            });
        }

        // Update the rest of the handlers to use BannerManager
        const acceptButton = document.getElementById("accept-btn");
        if (acceptButton) {
            acceptButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleAcceptAllConsent();
                bannerManager.hideAll();
            });
        }

        const declineButton = document.getElementById("decline-btn");
        if (declineButton) {
            declineButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleRejectAllConsent();
                bannerManager.hideAll();
            });
        }

        const savePreferencesButton = document.getElementById("save-preferences-btn");
        if (savePreferencesButton) {
            savePreferencesButton.addEventListener("click", async function(e) {
                e.preventDefault();
                const form = document.getElementById("main-banner") || 
                            document.getElementById("main-consent-banner");
                await handlePreferencesSave(form);
                bannerManager.hideAll();
            });
        }

        const doNotShareCheckbox = document.querySelector('[data-consent-id="do-not-share-checkbox"]');
        if (doNotShareCheckbox) {
            doNotShareCheckbox.addEventListener("change", async function(e) {
                await handleCCPAToggle(e.target.checked);
            });
        }

        const cancelButton = document.getElementById("cancel-btn");
        if (cancelButton) {
            cancelButton.addEventListener("click", async function(e) {
                e.preventDefault();
                await handleRejectAllConsent();
                bannerManager.hideAll();
            });
        }
    }

    // Update initialization for different banner types
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

            // Ensure BannerManager exists
            if (!window.bannerManager) {
                console.log("Creating new BannerManager instance");
                window.bannerManager = new BannerManager();
            }

            const consentGiven = localStorage.getItem("consent-given");

            // Hide all banners initially
            window.bannerManager.hideAll();

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
                const initialPreferences = {
                    Necessary: true,
                    Marketing: true,
                    Personalization: true,
                    Analytics: true,
                    DoNotShare: false
                };
                await restoreAllowedScripts(initialPreferences);
                window.bannerManager.show('ccpa');
            } else {
                console.log("Initializing GDPR banner");
                await scanAndBlockScripts();
                window.bannerManager.show('main');
            }

        } catch (error) {
            ScriptVerification.logError('initializeBannerVisibility', error);
            console.error("Failed to initialize banner visibility:", error);
            
            // Ensure BannerManager exists even in error case
            if (!window.bannerManager) {
                window.bannerManager = new BannerManager();
            }
            
            // Fallback to GDPR banner in case of error
            window.bannerManager.show('main');
            await scanAndBlockScripts();
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
            const visitorId = await getOrCreateVisitorId();
            const siteName = cleanHostname(window.location.hostname);
            
            let token = localStorage.getItem('visitorSessionToken');
            if (token && !isTokenExpired(token)) {
                return token;
            }

            const response = await fetch('https://cb-server.web-8fb.workers.dev/api/visitor-token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${CONFIG.API_KEY}`
                },
                body: JSON.stringify({
                    visitorId,
                    userAgent: navigator.userAgent,
                    siteName
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to get visitor token: ${response.status}`);
            }

            const data = await response.json();
            localStorage.setItem('visitorSessionToken', data.token);
            return data.token;
        } catch (error) {
            console.error('Error getting visitor session token:', error);
            return null;
        }
    }

    // Storage management utilities
    const StorageManager = {
        get: function(key) {
            try {
                return localStorage.getItem(key);
            } catch (e) {
                console.warn('Failed to get from storage:', e);
                return null;
            }
        },
        set: function(key, value) {
            try {
                localStorage.setItem(key, value);
                return true;
            } catch (e) {
                console.warn('Failed to save to storage:', e);
                return false;
            }
        },
        remove: function(key) {
            try {
                localStorage.removeItem(key);
                return true;
            } catch (e) {
                console.warn('Failed to remove from storage:', e);
                return false;
            }
        }
    };

    function blockAllInitialRequests() {
        console.log("Setting up initial request blocking...");

        // Block global analytics objects with enhanced logging
        const analyticsBlocker = {
            get: function(target, prop) {
                return function(...args) {
                    console.log(`🚫 Blocked ${prop} call with args:`, args);
                    return undefined;
                };
            },
            set: function(target, prop, value) {
                console.log(`🚫 Blocked setting ${prop}:`, value);
                return true;
            }
        };

        // Create a proxy for array-like objects with better error handling
        const createArrayProxy = () => {
            const handler = {
                get: function(target, prop) {
                    // Handle array methods
                    if (prop === 'push' || prop === 'unshift' || prop === 'splice') {
                        return function(...args) {
                            console.log(`🚫 Blocked array ${prop} with args:`, args);
                            return target.length;
                        };
                    }
                    // Handle array properties
                    if (prop === 'length') {
                        return target.length;
                    }
                    // Handle array access
                    if (typeof prop === 'number' || !isNaN(parseInt(prop))) {
                        return undefined;
                    }
                    // Handle other properties/methods
                    return function(...args) {
                        console.log(`🚫 Blocked array method ${prop} with args:`, args);
                        return undefined;
                    };
                },
                set: function(target, prop, value) {
                    console.log(`🚫 Blocked array set ${prop}:`, value);
                    return true;
                }
            };
            return new Proxy([], handler);
        };

        // Helper function to safely define or override a property
        const safeDefineProperty = (obj, prop, value) => {
            try {
                // First try to delete the existing property if it exists
                delete obj[prop];
                
                // Then define the new property
                Object.defineProperty(obj, prop, {
                    value: value,
                    writable: true,
                    configurable: true
                });
            } catch (e) {
                // If we can't delete/redefine, try to just set it
                try {
                    obj[prop] = value;
                } catch (e2) {
                    console.warn(`Could not block ${prop}:`, e2);
                }
            }
        };

        // Create blocked function with error handling
        const createBlockedFunction = (name) => {
            return function(...args) {
                try {
                    const safeArgs = args.map(arg => {
                        if (typeof arg === 'symbol') {
                            return arg.toString();
                        }
                        return arg;
                    });
                    console.log(`🚫 Blocked ${name} call with args:`, safeArgs);
                } catch (e) {
                    console.log(`🚫 Blocked ${name} call`);
                }
                return undefined;
            };
        };

        // Enhanced analytics properties to block
        const analyticsProps = {
            // Google Analytics
            'gtag': createBlockedFunction('gtag'),
            'ga': createBlockedFunction('ga'),
            'dataLayer': createArrayProxy(),
            'google_tag_manager': new Proxy({}, analyticsBlocker),
            
            // Plausible
            'plausible': createBlockedFunction('plausible'),
            
            // Matomo
            '_paq': createArrayProxy(),
            
            // Microsoft Clarity
            'clarity': new Proxy(createBlockedFunction('clarity'), {
                get: (target, prop) => {
                    if (prop === 'q') return [];
                    return target;
                }
            }),
            
            // HubSpot
            '_hsq': createArrayProxy(),
            'HubSpotAnalytics': new Proxy({}, analyticsBlocker),
            
            // Hotjar
            'hj': createBlockedFunction('hj'),
            '_hjSettings': new Proxy({}, analyticsBlocker),
            
            // Additional Clarity properties
            'clarityInstance': new Proxy({}, analyticsBlocker)
        };

        // Safely define all properties
        Object.entries(analyticsProps).forEach(([prop, value]) => {
            safeDefineProperty(window, prop, value);
        });

        // Block script injection attempts
        const originalCreateElement = document.createElement;
        document.createElement = function(tagName, options) {
            const element = originalCreateElement.call(document, tagName, options);
            
            if (tagName.toLowerCase() === 'script') {
                const originalSetAttribute = element.setAttribute;
                element.setAttribute = function(name, value) {
                    if (name === 'src' && state.initialBlockingEnabled && isSuspiciousResource(value)) {
                        console.log('🚫 Blocked script setAttribute:', value);
                        return;
                    }
                    return originalSetAttribute.call(this, name, value);
                };

                // Block direct src assignment
                let srcValue = '';
                Object.defineProperty(element, 'src', {
                    get: function() {
                        return srcValue;
                    },
                    set: function(value) {
                        if (state.initialBlockingEnabled && isSuspiciousResource(value)) {
                            console.log('🚫 Blocked script src:', value);
                            return;
                        }
                        srcValue = value;
                    },
                    configurable: true
                });
            }
            
            return element;
        };

        // Block fetch requests
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const url = args[0]?.url || args[0];
            if (state.initialBlockingEnabled && isSuspiciousResource(url)) {
                console.log('🚫 Blocked fetch request to:', url);
                return Promise.resolve(new Response(null, { status: 204 }));
            }
            return originalFetch.apply(this, args);
        };

        // Block XMLHttpRequest
        const originalXHR = window.XMLHttpRequest;
        window.XMLHttpRequest = function() {
            const xhr = new originalXHR();
            const originalOpen = xhr.open;
            xhr.open = function(method, url) {
                if (state.initialBlockingEnabled && isSuspiciousResource(url)) {
                    console.log('🚫 Blocked XHR request to:', url);
                    return;
                }
                return originalOpen.apply(xhr, arguments);
            };
            return xhr;
        };

        console.log("✅ Initial request blocking setup complete");
        
        // Log blocking status
        console.log("Analytics Blocking Status:");
        Object.entries(analyticsProps).forEach(([name, obj]) => {
            console.log(`${name}: ${typeof window[name]} ${window[name] ? '(blocked)' : '(undefined)'}`);
        });
    }

    // Initialize on DOM load with better error handling
    document.addEventListener('DOMContentLoaded', async () => {
        try {
            await initialize();
            
            // Show the main banner if no consent is given
            if (!StorageManager.get(CONFIG.STORAGE_KEYS.CONSENT_GIVEN)) {
                const mainBanner = document.getElementById('consent-banner');
                if (mainBanner) {
                    mainBanner.style.visibility = 'visible';
                    mainBanner.style.opacity = '1';
                    mainBanner.style.display = 'block';
                    mainBanner.classList.add('show-banner');
                    mainBanner.classList.remove('hidden');
                }
            }
        } catch (error) {
            console.error('Error during initialization:', error);
            ScriptVerification.logError('initialization', error);
            
            // Fallback initialization
            try {
                state.initialBlockingEnabled = true;
                blockAllInitialRequests();
                
                if (!window.bannerManager) {
                    window.bannerManager = new BannerManager();
                }
            } catch (fallbackError) {
                console.error('Critical: Fallback initialization failed:', fallbackError);
            }
        }
    });

    // Export necessary functions to window
    Object.assign(window, {
        acceptAllCookies: () => handleAcceptAllConsent(),
        blockAllCookies: () => handleRejectAllConsent(),
        loadConsentStyles: () => loadConsentStyles(),
        initializeConsent: () => initialize(),
        unblockAllCookiesAndTools: async () => {
            await handleAcceptAllConsent();
            return true;
        },
        updatePreferenceForm: (prefs) => {
            const form = document.getElementById("main-banner") || 
                        document.getElementById("main-consent-banner");
            if (form) {
                handlePreferencesSave(form);
            }
        },
        loadAndApplySavedPreferences: async () => {
            const preferences = await ConsentManager.loadConsent();
            if (preferences) {
                await restoreAllowedScripts(preferences);
                return preferences;
            }
            return null;
        },
        blockAllScripts: () => scanAndBlockScripts(),
        setDebugMode: (enabled) => {
            state.isDebugMode = enabled;
            localStorage.setItem(CONFIG.STORAGE_KEYS.DEBUG_MODE, enabled);
            Utils.debugLog(`Debug mode ${enabled ? 'enabled' : 'disabled'}`, 'info');
        },
        getDebugLogs: () => {
            return JSON.parse(localStorage.getItem('consent-debug-logs') || '[]');
        }
    });
})();

   
   

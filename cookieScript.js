async function restoreAllowedScripts(preferences) {
    console.log("RESTORE STARTS");

    // Normalize preferences keys to lowercase for consistent checking
    const normalizedPrefs = Object.fromEntries(
        Object.entries(preferences).map(([key, value]) => [key.toLowerCase(), value])
    );

    // Ensure 'necessary' is always true
    normalizedPrefs.necessary = true;

    console.log("Scripts to potentially restore:", Object.keys(existing_Scripts).length);
    console.log("Current preferences:", normalizedPrefs);

    // Iterate over a copy of the keys, as we might modify the object during iteration
    const scriptIdsToRestore = Object.keys(existing_Scripts);

    for (const scriptId of scriptIdsToRestore) {
        const scriptInfo = existing_Scripts[scriptId];
        if (!scriptInfo) continue; // Should not happen, but safety check

        // Find the placeholder in the DOM
        const placeholder = document.querySelector(`script[data-consentbit-id="${scriptId}"]`);
        if (!placeholder) {
            console.warn(`Placeholder for script ID ${scriptId} not found in DOM. Skipping restore.`);
            // Clean up the entry if the placeholder is gone
            delete existing_Scripts[scriptId];
            continue;
        }

        // Determine if the script is allowed based on its categories and current preferences
        // Either it's necessary, or at least one of its categories is allowed
        const isAllowed = scriptInfo.category.includes('necessary') || 
                         scriptInfo.category.some(cat => normalizedPrefs[cat] === true);

        console.log(`Script ID: ${scriptId}, Categories: [${scriptInfo.category.join(',')}], Allowed: ${isAllowed}`);

        if (isAllowed) {
            // Check if a script with this src already exists in the DOM (prevent duplicates)
            if (scriptInfo.src) {
                 // More specific check: Look for scripts with the same src that are NOT placeholders
                const existingScript = document.querySelector(`script[src="${scriptInfo.src}"]:not([type='text/plain'])`);
                if (existingScript && existingScript !== placeholder) {
                    console.log(`Script with src ${scriptInfo.src} already exists. Skipping restore for ID ${scriptId}.`);
                     // Remove the placeholder if the script already exists elsewhere
                    if (placeholder.parentNode) {
                         placeholder.parentNode.removeChild(placeholder);
                     }
                    delete existing_Scripts[scriptId]; // Clean up the reference
                    continue; // Move to the next script
                }
            }

            console.log(`Restoring script ID: ${scriptId} (${scriptInfo.src || 'inline'})`);
            const script = document.createElement("script");

            // Restore core properties
            script.type = scriptInfo.type; // Restore original type
            if (scriptInfo.async) script.async = true;
            if (scriptInfo.defer) script.defer = true;
            script.setAttribute("data-category", scriptInfo.category.join(',')); // Keep category info if needed

            // Restore src or content
            if (scriptInfo.src) {
                script.src = scriptInfo.src;

                // --- ANALYTICS TOOL INTEGRATIONS ---
                
                // 1. Google Analytics
                if (/googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js/i.test(scriptInfo.src)) {
                    setupGtagConsent(script, normalizedPrefs);
                }
                
                // 2. Microsoft Clarity
                else if (/clarity\.ms/i.test(scriptInfo.src)) {
                    setupClarityConsent(script, normalizedPrefs);
                }
                
                // 3. Facebook Pixel
                else if (/connect\.facebook\.net\/.*fbevents\.js/i.test(scriptInfo.src)) {
                    setupFacebookConsent(script, normalizedPrefs);
                }
                
                // 4. Matomo
                else if (/matomo\.js/i.test(scriptInfo.src)) {
                    setupMatomoConsent(script, normalizedPrefs);
                }
                
                // 5. HubSpot
                else if (/js\.hs-scripts\.com|js\.hubspot\.com/i.test(scriptInfo.src)) {
                    setupHubSpotConsent(script, normalizedPrefs);
                }
                
                // 6. Plausible
                else if (/plausible\.io/i.test(scriptInfo.src)) {
                    setupPlausibleConsent(script, normalizedPrefs);
                }
                
                // 7. Hotjar
                else if (/static\.hotjar\.com/i.test(scriptInfo.src)) {
                    setupHotjarConsent(script, normalizedPrefs);
                }
                
                // Default: Just restore attributes for other scripts
                else {
                    Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                        script.setAttribute(name, value);
                    });
                }

            } else {
                script.textContent = scriptInfo.content;
                // Restore other attributes for inline scripts
                Object.entries(scriptInfo.originalAttributes).forEach(([name, value]) => {
                    script.setAttribute(name, value);
                });
            }

            // Replace the placeholder with the restored script
            if (placeholder.parentNode) {
                placeholder.parentNode.replaceChild(script, placeholder);
            } else {
                console.warn(`Placeholder parent node not found for script ID ${scriptId}. Appending to head.`);
                document.head.appendChild(script); // Fallback: append to head
            }

            // Remove the script info from our tracking object *after* successful restoration
            delete existing_Scripts[scriptId];

        } else {
            console.log(`Script ID: ${scriptId} remains blocked.`);
            // Ensure the node in the DOM is still a placeholder (it should be)
            if (placeholder.tagName !== 'SCRIPT' || placeholder.type !== 'text/plain') {
                console.warn(`Node for script ID ${scriptId} is not a placeholder as expected.`);
            }
        }
    }

    console.log("Scripts remaining in existing_Scripts map:", Object.keys(existing_Scripts).length);
    console.log("RESTORE ENDS");
    
    // Disable initial blocking after restoration
    initialBlockingEnabled = false;
}

// --- Consent Update Helper Functions ---
// 1. Google Analytics
function setupGtagConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Google Analytics consent integration");
    
    function updateGAConsent() {
        if (typeof window.gtag === "function") {
            console.log("Updating GA consent settings...");
            window.gtag('consent', 'update', {
                'ad_storage': normalizedPrefs.marketing ? 'granted' : 'denied',
                'analytics_storage': normalizedPrefs.analytics ? 'granted' : 'denied',
                'ad_personalization': normalizedPrefs.personalization ? 'granted' : 'denied',
                'ad_user_data': normalizedPrefs.marketing ? 'granted' : 'denied',
                'functionality_storage': 'granted', // Usually necessary
                'personalization_storage': normalizedPrefs.personalization ? 'granted' : 'denied',
                'security_storage': 'granted' // Security is always necessary
            });
        } else {
            console.warn("gtag function not available yet");
        }
    }
    
    // Attempt immediate update
    updateGAConsent();
    
    // Also update after script loads
    scriptElement.onload = () => {
        console.log("GA script loaded, updating consent");
        updateGAConsent();
        
        // Restore attributes after load if needed
        Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
            scriptElement.setAttribute(name, value);
        });
    };
    
    scriptElement.onerror = () => console.error("Failed to load GA script");
}

// 2. Microsoft Clarity
function setupClarityConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Microsoft Clarity consent integration");
    
    const hasAnalyticsConsent = normalizedPrefs.analytics === true;
    
    if (!hasAnalyticsConsent) {
        // If analytics consent is denied, we prevent Clarity from initializing
        // by injecting a blocking script before loading Clarity
        const blockingScript = document.createElement('script');
        blockingScript.textContent = `
            window.clarity = window.clarity || {};
            window.clarity.consent = false;
            window.clarity.disabled = true;
        `;
        document.head.appendChild(blockingScript);
    } else {
        // If consent is granted, we explicitly enable Clarity
        const enableScript = document.createElement('script');
        enableScript.textContent = `
            window.clarity = window.clarity || {};
            window.clarity.consent = true;
        `;
        document.head.appendChild(enableScript);
    }
    
    // Restore attributes but add onload handler
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}

// 3. Facebook Pixel
function setupFacebookConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Facebook Pixel consent integration");
    
    const hasMarketingConsent = normalizedPrefs.marketing === true;
    
    function updateFBConsent() {
        if (typeof window.fbq === 'function') {
            console.log(`Setting Facebook Pixel consent to: ${hasMarketingConsent ? 'grant' : 'revoke'}`);
            window.fbq('consent', hasMarketingConsent ? 'grant' : 'revoke');
        } else {
            console.warn("fbq function not available yet");
        }
    }
    
    // Attempt immediate update
    updateFBConsent();
    
    // Also update when script loads
    scriptElement.onload = () => {
        console.log("Facebook Pixel script loaded, updating consent");
        updateFBConsent();
    };
    
    // Restore attributes
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}

// 4. Matomo
function setupMatomoConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Matomo consent integration");
    
    const hasAnalyticsConsent = normalizedPrefs.analytics === true;
    
    function updateMatomoConsent() {
        if (typeof window._paq === 'object' && window._paq.push) {
            console.log(`Setting Matomo consent to: ${hasAnalyticsConsent ? 'given' : 'revoked'}`);
            if (hasAnalyticsConsent) {
                window._paq.push(['setConsentGiven']);
                window._paq.push(['trackPageView']);
            } else {
                window._paq.push(['forgetConsentGiven']);
            }
        } else {
            console.warn("_paq object not available yet");
        }
    }
    
    // Attempt immediate update
    updateMatomoConsent();
    
    // Also update when script loads
    scriptElement.onload = () => {
        console.log("Matomo script loaded, updating consent");
        updateMatomoConsent();
    };
    
    // Restore attributes
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}

// 5. HubSpot
function setupHubSpotConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up HubSpot consent integration");
    
    // HubSpot typically needs marketing and/or analytics consent
    const hasConsent = normalizedPrefs.marketing === true || 
                      normalizedPrefs.analytics === true;
    
    function updateHubSpotConsent() {
        if (typeof window._hsq === 'object' && window._hsq.push) {
            console.log(`Setting HubSpot consent to: ${hasConsent ? 'granted' : 'denied'}`);
            if (!hasConsent) {
                window._hsq.push(['doNotTrack']);
            } else {
                window._hsq.push(['doNotTrack', { track: true }]);
            }
        } else {
            console.warn("_hsq object not available yet");
        }
    }
    
    // Attempt immediate update
    updateHubSpotConsent();
    
    // Also update when script loads
    scriptElement.onload = () => {
        console.log("HubSpot script loaded, updating consent");
        updateHubSpotConsent();
    };
    
    // Restore attributes
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}

// 6. Plausible (Note: Plausible doesn't have a consent API, we just allow/block it)
function setupPlausibleConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Plausible Analytics consent");
    
    // Plausible is privacy-friendly and doesn't have a JavaScript consent API
    // We just don't load it if consent is denied, but we can add a data attribute
    // to indicate consent was given when loaded
    
    if (normalizedPrefs.analytics === true) {
        scriptElement.setAttribute('data-consent-given', 'true');
    }
    
    // Restore attributes
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}

// 7. Hotjar
function setupHotjarConsent(scriptElement, normalizedPrefs) {
    console.log("Setting up Hotjar consent integration");
    
    // Hotjar usually requires marketing or analytics consent
    const hasConsent = normalizedPrefs.marketing === true || 
                      normalizedPrefs.analytics === true;
    
    // Set up Hotjar consent flags before the script loads
    const setupScript = document.createElement('script');
    setupScript.textContent = `
        window.hj = window.hj || function(){(window.hj.q = window.hj.q || []).push(arguments)};
        window._hjSettings = window._hjSettings || {};
        window._hjSettings.consent = ${hasConsent};
    `;
    document.head.appendChild(setupScript);
    
    function updateHotjarConsent() {
        if (typeof window.hj === 'function') {
            console.log(`Setting Hotjar consent to: ${hasConsent ? 'granted' : 'denied'}`);
            if (hasConsent) {
                window.hj('consent', 'granted');
            } else {
                window.hj('consent', 'declined');
            }
        } else {
            console.warn("hj function not available yet");
        }
    }
    
    // Attempt immediate update
    updateHotjarConsent();
    
    // Also update when script loads
    scriptElement.onload = () => {
        console.log("Hotjar script loaded, updating consent");
        updateHotjarConsent();
    };
    
    // Restore attributes
    Object.entries(scriptInfo.originalAttributes || {}).forEach(([name, value]) => {
        scriptElement.setAttribute(name, value);
    });
}
// Add similar setup functions (e.g., setupHubSpotConsent, setup...) for other tools if they have specific JS APIs.

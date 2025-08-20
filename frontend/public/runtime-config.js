/**
 * Runtime Configuration Helper for Vulnera Frontend
 * 
 * This script allows configuring the Vulnera frontend at runtime
 * without rebuilding. Useful for Docker containers, CDN deployments,
 * or when you need to change configuration after build.
 * 
 * Usage:
 * Include this script in your index.html before the main app:
 * <script src="/runtime-config.js"></script>
 * 
 * Or set window variables directly:
 * <script>
 *   window.VULNERA_API_BASE_URL = 'https://api.example.com';
 *   window.VULNERA_API_VERSION = 'v1';
 *   window.VULNERA_APP_NAME = 'Custom Vulnera';
 * </script>
 */

(function() {
  'use strict';
  
  // Runtime configuration object
  window.VulneraRuntimeConfig = {
    
    /**
     * Set API configuration at runtime
     * @param {Object} config - Configuration object
     * @param {string} config.apiBaseUrl - API base URL
     * @param {string} config.apiVersion - API version
     * @param {string} config.appName - Application name
     * @param {string} config.appVersion - Application version
     * @param {boolean} config.enableDebug - Enable debug mode
     * @param {number} config.apiTimeout - API timeout in milliseconds
     * @param {string} config.environment - Environment name
     */
    setConfig: function(config) {
      if (config.apiBaseUrl) {
        window.VULNERA_API_BASE_URL = config.apiBaseUrl;
      }
      if (config.apiVersion) {
        window.VULNERA_API_VERSION = config.apiVersion;
      }
      if (config.appName) {
        window.VULNERA_APP_NAME = config.appName;
      }
      if (config.appVersion) {
        window.VULNERA_APP_VERSION = config.appVersion;
      }
      if (config.enableDebug !== undefined) {
        window.VULNERA_ENABLE_DEBUG = String(config.enableDebug);
      }
      if (config.apiTimeout) {
        window.VULNERA_API_TIMEOUT = String(config.apiTimeout);
      }
      if (config.environment) {
        window.VULNERA_ENVIRONMENT = config.environment;
      }
      
      console.log('✅ Vulnera runtime configuration updated:', this.getConfig());
    },
    
    /**
     * Get current runtime configuration
     * @returns {Object} Current configuration
     */
    getConfig: function() {
      return {
        apiBaseUrl: window.VULNERA_API_BASE_URL,
        apiVersion: window.VULNERA_API_VERSION,
        appName: window.VULNERA_APP_NAME,
        appVersion: window.VULNERA_APP_VERSION,
        enableDebug: window.VULNERA_ENABLE_DEBUG,
        apiTimeout: window.VULNERA_API_TIMEOUT,
        environment: window.VULNERA_ENVIRONMENT
      };
    },
    
    /**
     * Load configuration from a JSON endpoint
     * @param {string} configUrl - URL to fetch configuration from
     * @returns {Promise} Promise that resolves when config is loaded
     */
    loadFromUrl: function(configUrl) {
      return fetch(configUrl)
        .then(function(response) {
          if (!response.ok) {
            throw new Error('Failed to load configuration from ' + configUrl);
          }
          return response.json();
        })
        .then(function(config) {
          this.setConfig(config);
          return config;
        }.bind(this))
        .catch(function(error) {
          console.warn('⚠️ Failed to load runtime configuration:', error);
          throw error;
        });
    },
    
    /**
     * Auto-detect configuration based on current domain
     */
    autoDetectConfig: function() {
      const hostname = window.location.hostname;
      const protocol = window.location.protocol;
      
      let config = {};
      
      // Auto-detect based on hostname
      if (hostname === 'localhost' || hostname === '127.0.0.1') {
        config = {
          apiBaseUrl: 'http://localhost:3000',
          appName: 'Vulnera Dev',
          enableDebug: true,
          environment: 'development'
        };
      } else if (hostname.includes('staging') || hostname.includes('dev')) {
        config = {
          apiBaseUrl: protocol + '//' + hostname.replace(/^(staging|dev)\.?/, '') + ':3000',
          appName: 'Vulnera Staging',
          enableDebug: true,
          environment: 'staging'
        };
      } else {
        config = {
          apiBaseUrl: protocol + '//api.' + hostname,
          appName: 'Vulnera',
          enableDebug: false,
          environment: 'production'
        };
      }
      
      console.log('🔍 Auto-detected configuration for', hostname, ':', config);
      this.setConfig(config);
      return config;
    }
  };
  
  // Example configurations for common scenarios
  window.VulneraRuntimeConfig.examples = {
    
    development: {
      apiBaseUrl: 'http://localhost:3000',
      apiVersion: 'v1',
      appName: 'Vulnera Dev',
      enableDebug: true,
      apiTimeout: 30000,
      environment: 'development'
    },
    
    staging: {
      apiBaseUrl: 'https://vulnera-back.politeisland-d68133bc.switzerlandnorth.azurecontainerapps.io',
      apiVersion: 'v1',
      appName: 'Vulnera Staging',
      enableDebug: true,
      apiTimeout: 60000,
      environment: 'staging'
    },
    
    production: {
      apiBaseUrl: 'https://api.vulnera.dev',
      apiVersion: 'v1',
      appName: 'Vulnera',
      enableDebug: false,
      apiTimeout: 60000,
      environment: 'production'
    },
    
    network: function(ip) {
      return {
        apiBaseUrl: 'http://' + ip + ':3000',
        apiVersion: 'v1',
        appName: 'Vulnera Network',
        enableDebug: true,
        apiTimeout: 30000,
        environment: 'development'
      };
    }
  };
  
  // Helper function to quickly switch environments
  window.VulneraRuntimeConfig.useExample = function(exampleName) {
    const example = this.examples[exampleName];
    if (example) {
      this.setConfig(example);
      return example;
    } else {
      console.error('❌ Unknown example configuration:', exampleName);
      console.log('Available examples:', Object.keys(this.examples));
      return null;
    }
  };
  
  console.log('🔧 Vulnera Runtime Configuration Helper loaded');
  console.log('   Usage: VulneraRuntimeConfig.setConfig({apiBaseUrl: "https://api.example.com"})');
  console.log('   Examples: VulneraRuntimeConfig.useExample("staging")');
  
})();

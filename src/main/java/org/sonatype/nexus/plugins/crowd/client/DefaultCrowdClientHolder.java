/*
 * Copyright (c) 2010 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.sonatype.nexus.plugins.crowd.client;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;
import org.codehaus.plexus.logging.AbstractLogEnabled;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Initializable;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.plugins.crowd.caching.AuthBasicCache;
import org.sonatype.nexus.plugins.crowd.caching.AuthBasicCacheImpl;
import org.sonatype.nexus.plugins.crowd.caching.CachingAuthenticationManager;
import org.sonatype.nexus.plugins.crowd.config.CrowdPluginConfiguration;
import org.sonatype.nexus.plugins.crowd.config.model.v1_0_0.Configuration;

import java.util.Properties;

/**
 * Implementation of the CrowdClientHolder which uses caching wherever possible.
 *
 * @author Justin Edelson
 * @author Issa Gorissen
 */
@Singleton
@Typed(CrowdClientHolder.class)
@Named("default")
public class DefaultCrowdClientHolder extends AbstractLogEnabled implements CrowdClientHolder, Initializable {

    private boolean configured = false;
    private AuthBasicCache basicCache;
    private Configuration configuration;
    private CachingAuthenticationManager authManager;

    private ClientProperties clientProperties;
    private CrowdClient crowdClient;
    private CrowdHttpAuthenticator crowdHttpAuthenticator;

    private static final Logger logger = LoggerFactory.getLogger(DefaultCrowdClientHolder.class);

    @Inject
    private CrowdPluginConfiguration crowdPluginConfiguration;

    public void initialize() throws InitializationException {
        configuration = crowdPluginConfiguration.getConfiguration();
        if (configuration != null) {
            Properties crowdProperties = convertToCrowdProperties(configuration);
            clientProperties = ClientPropertiesImpl.newInstanceFromProperties(crowdProperties);
            crowdClient = new RestCrowdClientFactory().newInstance(clientProperties);
            crowdHttpAuthenticator = new CrowdHttpAuthenticatorImpl(crowdClient, clientProperties, CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance()));

            logger.debug("Configuring crowd with url: {} app name: {}", configuration.getCrowdServerUrl(), configuration.getApplicationName());
            basicCache = new AuthBasicCacheImpl(60 * configuration.getSessionValidationInterval());
            crowdClient = new RestCrowdClientFactory().newInstance(configuration.getCrowdServerUrl(), configuration.getApplicationName(), configuration.getApplicationPassword());
            authManager = new CachingAuthenticationManager(crowdClient, basicCache);
            configured = true;
        } else {
            logger.warn("Configuration was empty, could not set crowd plugin configurations.");
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isConfigured() {
        return configured;
    }

    public CachingAuthenticationManager getAuthenticationManager() {
    	return authManager;
    }

    public CrowdClient getCrowdClient() {
        return crowdClient;
    }

    public CrowdHttpAuthenticator getCrowdHttpAuthenticator() {
        return crowdHttpAuthenticator;
    }

    private Properties convertToCrowdProperties(Configuration configuration) {
        Properties properties = new Properties();
        properties.put("application.name", configuration.getApplicationName());
        properties.put("application.password", configuration.getApplicationPassword());
        properties.put("application.login.url", configuration.getCrowdServerUrl());
        properties.put("cookie.tokenkey", configuration.getCrowdCookieTokenKey());
        properties.put("cookie.domain", configuration.getCrowdCookieDomain());
        properties.put("crowd.server.url", configuration.getCrowdServerUrl());
        return properties;
    }
}

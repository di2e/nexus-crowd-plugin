/**
 * Copyright (C) 2017 DI2E (www.di2e.net)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sonatype.nexus.plugins.crowd.token;

import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.service.client.CrowdClient;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.plugins.crowd.client.CrowdClientHolder;
import org.sonatype.nexus.security.filter.authc.AuthenticationTokenFactory;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementation for AuthenticationTokenFactory that creates AuthenticationTokens from cookie-based Crowd SSO tokens.
 *
 * @author Matt Ramey (mrmateo)
 *
 */
@Singleton
@Typed(AuthenticationTokenFactory.class)
@Named
public class CrowdTokenAuthenticationTokenFactory implements AuthenticationTokenFactory {

    @Inject
    private CrowdClientHolder crowdClientHolder;

    private static final Logger logger = LoggerFactory.getLogger(CrowdTokenAuthenticationTokenFactory.class);

    @Override
    public AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        CrowdClient crowdClient = crowdClientHolder.getCrowdClient();
        CrowdHttpAuthenticator crowdHttpAuthenticator = crowdClientHolder.getCrowdHttpAuthenticator();
        String token = crowdHttpAuthenticator.getToken(httpServletRequest);
        if (token != null) {
            try {
                crowdClient.validateSSOAuthentication(token, CrowdHttpValidationFactorExtractorImpl.getInstance().getValidationFactors(httpServletRequest));
                return new CrowdTokenAuthenticationToken(token, token, request.getRemoteHost());
            } catch (Exception e) {
                logger.warn("Could not check incoming authentication for crowd token.", e);
            }
        } else {
            logger.info("Did not find token in incoming request.");
        }
        return null;
    }


}


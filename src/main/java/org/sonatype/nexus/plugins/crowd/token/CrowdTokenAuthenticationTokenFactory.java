/**
 * Copyright (C) 2017 DI2E (www.di2e.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sonatype.nexus.plugins.crowd.token;

import com.atlassian.crowd.model.authentication.CookieConfiguration;
import com.atlassian.crowd.service.client.CrowdClient;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.util.WebUtils;
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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

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

    private static final String DEFAULT_CROWD_COOKIE_NAME = "crowd.token_key";
    private String crowdCookieName;

    private static final Logger logger = LoggerFactory.getLogger(CrowdTokenAuthenticationTokenFactory.class);

    @Override
    public AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        if (crowdCookieName == null) {
            setCrowdCookieName();
        }
        // get crowd token from request
        Map<String, String> cookieMap = getCookieMap(WebUtils.toHttp(request));
        if (cookieMap.containsKey(crowdCookieName)) {
            logger.debug("Found a cookie with name {} and value {}, returning a CrowdTokenAuthToken.", crowdCookieName, cookieMap.get(crowdCookieName));
            String crowdToken = cookieMap.get(crowdCookieName);
            return new CrowdTokenAuthenticationToken(crowdToken, crowdToken, request.getRemoteHost());
        } else {
            logger.warn("Did not find a cookie with name {}", crowdCookieName);
        }
        return null;
    }

    private Map<String, String> getCookieMap(HttpServletRequest request) {
        Map<String, String> cookieMap = new HashMap<>();
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookieMap.put(cookie.getName(), cookie.getValue());
            }
        }
        return cookieMap;
    }

    private synchronized void setCrowdCookieName() {
        try {
            CrowdClient crowdClient = crowdClientHolder.getCrowdClient();
            CookieConfiguration cookieConfig = crowdClient.getCookieConfiguration();
            crowdCookieName = cookieConfig.getName();
        } catch (Exception e) {
            logger.warn("Could not retrieve cookie configuration from server, defaulting to cookie name of " + DEFAULT_CROWD_COOKIE_NAME, e);
            crowdCookieName = DEFAULT_CROWD_COOKIE_NAME;
        }
    }

}

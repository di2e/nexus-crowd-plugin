/**
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
/**
 * 
 */
package org.sonatype.nexus.plugins.crowd.caching;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.integration.rest.entity.ValidationFactorEntityList;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * Implementation of Crowd client's AuthenticationManager which caches tokens
 * from a username/password authentication request.
 * 
 * @author Justin Edelson
 * @author Issa Gorissen
 * 
 */
public class CachingAuthenticationManager {

    private AuthBasicCache basicCache;

    private CrowdClient crowdClient;

    public CachingAuthenticationManager(CrowdClient crowdClient, AuthBasicCache basicCache) {
    	this.crowdClient = crowdClient;
        this.basicCache = basicCache;
    }
  
    public String authenticate(String username, String password) throws Exception {
        assert username != null;
        assert password != null;

        String token = basicCache.getToken(username, password);
        if (token == null) {
            UserAuthenticationContext authenticationContext = createUserAuthContext(username, password);

            token = crowdClient.authenticateSSOUser(authenticationContext);

            basicCache.addOrReplaceToken(username, password, token);
        }
        return token;
    }

    private UserAuthenticationContext createUserAuthContext(String username, String password) {
        UserAuthenticationContext authenticationContext = new UserAuthenticationContext();
        authenticationContext.setName(username);
        authenticationContext.setCredential(new PasswordCredential(password));
        //TODO get application and validation factors dynamically
        authenticationContext.setApplication("nexus");
        //authenticationContext.setValidationFactors();
        return authenticationContext;
    }
 
}

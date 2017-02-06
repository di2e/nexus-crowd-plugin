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

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * Implementation for HostAuthenticationToken used for Crowd SSO tokens.
 *
 * @author Matt Ramey (mrmateo)
 *
 */
public class CrowdTokenAuthenticationToken implements HostAuthenticationToken {

    private String crowdToken;

    private Object credentials;

    private String host;

    public CrowdTokenAuthenticationToken (final String crowdToken, final Object credentials, final String host) {
        this.crowdToken = crowdToken;
        this.credentials = credentials;
        this.host = host;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public Object getPrincipal() {
        return crowdToken;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }
}

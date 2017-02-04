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
package org.sonatype.nexus.plugins.crowd;

import java.util.HashSet;
import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.atlassian.crowd.model.user.User;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Disposable;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.Initializable;
import org.codehaus.plexus.personality.plexus.lifecycle.phase.InitializationException;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.plugins.crowd.client.CrowdClientHolder;

@Singleton
@Typed(Realm.class)
@Named(CrowdAuthenticatingRealm.ROLE)
@Description("OSS Crowd Authentication Realm")
public class CrowdAuthenticatingRealm extends AuthorizingRealm implements Initializable, Disposable {

	public static final String ROLE = "NexusCrowdAuthenticationRealm";
	private static final String DEFAULT_MESSAGE = "Could not retrieve info from Crowd.";
	private static boolean active;

	@Inject
	private CrowdClientHolder crowdClientHolder;

	private static final Logger logger = LoggerFactory.getLogger(CrowdAuthenticatingRealm.class);

	public static boolean isActive() {
		return active;
	}

	public void dispose() {
		active = false;
		logger.info("Crowd Realm deactivated...");
	}

	@Override
	public String getName() {
		return CrowdAuthenticatingRealm.class.getName();
	}

	public void initialize() throws InitializationException {
		logger.info("Crowd Realm activated...");
		active = true;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		if (!(authenticationToken instanceof UsernamePasswordToken)) {
			throw new UnsupportedTokenException("Token of type " + authenticationToken.getClass().getName()
					+ " is not supported.  A " + UsernamePasswordToken.class.getName() + " is required.");
		}
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

		String password = new String(token.getPassword());

		try {
			User user = crowdClientHolder.getCrowdClient().authenticateUser(token.getUsername(), password);
			//TODO update to use local auth cache
			logger.debug("User {} successfully authenticated.", user.getName());
			return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
		} catch (Exception e) {
			throw new AuthenticationException(DEFAULT_MESSAGE, e);
		}
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String username = (String) principals.getPrimaryPrincipal();
		try {
			Set<String> groups = new HashSet<>(crowdClientHolder.getCrowdClient().getNamesOfGroupsForNestedUser(username, 0, 1000));
			return new SimpleAuthorizationInfo(groups);
		} catch (Exception e) {
			throw new AuthorizationException(DEFAULT_MESSAGE, e);
		}
	}
}

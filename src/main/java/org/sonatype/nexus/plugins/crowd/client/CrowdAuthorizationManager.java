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

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Collections;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.search.builder.Restriction;
import com.atlassian.crowd.search.query.entity.restriction.constants.UserTermKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.security.authorization.AbstractReadOnlyAuthorizationManager;
import org.sonatype.security.authorization.AuthorizationManager;
import org.sonatype.security.authorization.NoSuchPrivilegeException;
import org.sonatype.security.authorization.NoSuchRoleException;
import org.sonatype.security.authorization.Privilege;
import org.sonatype.security.authorization.Role;

/**
 * @author justin
 * @author Issa Gorissen
 */
@Singleton
@Typed(AuthorizationManager.class)
@Named("Crowd")
public class CrowdAuthorizationManager extends AbstractReadOnlyAuthorizationManager {

    @Inject
    private CrowdClientHolder crowdClientHolder;

    private static final Logger logger = LoggerFactory.getLogger(CrowdAuthorizationManager.class);

    public CrowdAuthorizationManager() {
        logger.info("CrowdAuthorizationManager is starting...");
    }

    /**
     * {@inheritDoc}
     */
    public Privilege getPrivilege(String privilegeId) throws NoSuchPrivilegeException {
        throw new NoSuchPrivilegeException("Crowd plugin doesn't support privileges");
    }

    /**
     * {@inheritDoc}
     */
    public Role getRole(String roleId) throws NoSuchRoleException {
        if (crowdClientHolder.isConfigured()) {
            try {
                Group crowdGroup = crowdClientHolder.getCrowdClient().getGroup(roleId);
                Role role = convertGroupToRole(crowdGroup);
                return role;
            } catch (Exception e) {
                throw new NoSuchRoleException("Failed to get role " + roleId + " from Crowd.", e);
            }
        } else {
            throw new NoSuchRoleException("Crowd plugin is not configured.");
        }
    }

    public String getSource() {
        return CrowdUserManager.SOURCE;
    }

    public Set<Privilege> listPrivileges() {
        return Collections.emptySet();
    }

    public Set<Role> listRoles() {
        if (crowdClientHolder.isConfigured()) {
            try {
                List<Group> crowdGroups = crowdClientHolder.getCrowdClient().searchGroups(Restriction.on(UserTermKeys.ACTIVE).exactlyMatching(Boolean.TRUE), 0, 1000);
            	Set<Role> roles = new HashSet<>();
            	for (Group group : crowdGroups) {
            	    roles.add(convertGroupToRole(group));
                }
                return roles;
            } catch (Exception e) {
                logger.error("Unable to load roles", e);
                return null;
            }
        }
        UnconfiguredNotifier.unconfigured();
        return Collections.emptySet();
    }

    private Role convertGroupToRole(Group group) {
        Role role = new Role();
        role.setName(group.getName());
        role.setSource(getSource());
        role.setDescription(group.getDescription());
        role.setReadOnly(true);
        role.setRoleId(group.getName());
        return role;
    }

}

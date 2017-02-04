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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.atlassian.crowd.embedded.api.SearchRestriction;
import com.atlassian.crowd.search.builder.Combine;
import com.atlassian.crowd.search.builder.Restriction;
import com.atlassian.crowd.search.query.entity.restriction.constants.UserTermKeys;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.security.usermanagement.AbstractReadOnlyUserManager;
import org.sonatype.security.usermanagement.DefaultUser;
import org.sonatype.security.usermanagement.RoleIdentifier;
import org.sonatype.security.usermanagement.User;
import org.sonatype.security.usermanagement.UserManager;
import org.sonatype.security.usermanagement.UserNotFoundException;
import org.sonatype.security.usermanagement.UserSearchCriteria;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import org.sonatype.security.usermanagement.UserStatus;

/**
 * @author justin
 * @author Issa Gorissen
 */
@Singleton
@Typed(UserManager.class)
@Named("Crowd")
public class CrowdUserManager extends AbstractReadOnlyUserManager {

    protected static final String REALM_NAME = "Crowd";

    protected static final String SOURCE = "Crowd";

    /**
     * The maximum number of results that will be returned from a user query.
     */
    private int maxResults = 1000;

    @Inject
    private CrowdClientHolder crowdClientHolder;

    private static final Logger logger = LoggerFactory.getLogger(CrowdUserManager.class);

    
    public CrowdUserManager() {
        logger.info("CrowdUserManager is starting...");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAuthenticationRealmName() {
        return REALM_NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSource() {
        return SOURCE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public User getUser(String userId) throws UserNotFoundException {
        if (crowdClientHolder.isConfigured()) {
            try {
                User user = convertUser(crowdClientHolder.getCrowdClient().getUser(userId));
                completeUserRolesAndSource(user);
                return user;
            } catch (Exception e) {
                logger.error("Unable to look up user " + userId, e);
                throw new UserNotFoundException(userId, e.getMessage(), e);
            }
        } else {
            throw new UserNotFoundException("Crowd plugin is not configured.");
        }
    }

    private Set<RoleIdentifier> getUsersRoles(String userId, String userSource) throws UserNotFoundException {
        if (SOURCE.equals(userSource)) {
            if (crowdClientHolder.isConfigured()) {
                List<String> roleNames = null;
                try {
                    roleNames = crowdClientHolder.getCrowdClient().getNamesOfGroupsForNestedUser(userId,0, 100);
                } catch (Exception e) {
                    logger.error("Unable to look up user " + userId, e);
                    return Collections.emptySet();
                }
                return Sets.newHashSet(Iterables.transform(roleNames, new Function<String, RoleIdentifier>() {

                    public RoleIdentifier apply(String from) {
                        return new RoleIdentifier(SOURCE, from);
                    }
                }));
            } else {
                throw new UserNotFoundException("Crowd plugin is not configured.");
            }
        } else {
            return Collections.emptySet();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> listUserIds() {
        if (crowdClientHolder.isConfigured()) {
            try {
                List<String> userList = crowdClientHolder.getCrowdClient().searchUserNames(Restriction.on(UserTermKeys.ACTIVE).exactlyMatching(Boolean.TRUE), 0, maxResults);
                return new HashSet<>(userList);
            } catch (Exception e) {
                logger.error("Unable to get username list", e);
                return Collections.emptySet();
            }
        } else {
            UnconfiguredNotifier.unconfigured();
            return Collections.emptySet();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<User> listUsers() {
        return searchUsers(new UserSearchCriteria());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<User> searchUsers(UserSearchCriteria criteria) {
        if (!crowdClientHolder.isConfigured()) {
            UnconfiguredNotifier.unconfigured();
            return Collections.emptySet();
        }
        
        if (!SOURCE.equals(criteria.getSource())) {
        	return Collections.emptySet();
        }

        try {
            Set<com.atlassian.crowd.model.user.User> userResults = new HashSet<>(crowdClientHolder.getCrowdClient()
                    .searchUsers(convertCriteria(criteria),0,maxResults));
            Set<User> returnUsers = new HashSet<>();
            if (!userResults.isEmpty()) {
                if (criteria.getOneOfRoleIds() != null && !criteria.getOneOfRoleIds().isEmpty()) {
                    // filter on group
                    for (com.atlassian.crowd.model.user.User curUser : userResults) {
                        Set<RoleIdentifier> roles = getUsersRoles(curUser.getName(), SOURCE);
                        for (RoleIdentifier role : roles) {
                            if (criteria.getOneOfRoleIds().contains(role.getRoleId())) {
                                User newUser = convertUser(curUser);
                                newUser.setRoles(roles);
                                newUser.setSource(SOURCE);
                                returnUsers.add(newUser);
                                break;
                            }
                        }
                    }
                } else {
                    for (com.atlassian.crowd.model.user.User curUser : userResults) {
                        User newUser = convertUser(curUser);
                        completeUserRolesAndSource(newUser);
                        returnUsers.add(newUser);
                    }
                }
            }

            return returnUsers;
            
        } catch (Exception e) {
            logger.error("Unable to get userlist", e);
            return Collections.emptySet();
        }
    }

    private void completeUserRolesAndSource(User user) throws UserNotFoundException {
        user.setSource(SOURCE);
       	user.setRoles(getUsersRoles(user.getUserId(), SOURCE));
    }

    private User convertUser(com.atlassian.crowd.model.user.User crowdUser) {
        User user = new DefaultUser();
        user.setFirstName(crowdUser.getFirstName());
        user.setLastName(crowdUser.getLastName());
        user.setEmailAddress(crowdUser.getEmailAddress());
        user.setUserId(crowdUser.getName());
        user.setStatus(convertStatus(crowdUser.isActive()));
        return user;
    }

    private UserStatus convertStatus(boolean isActive) {
        if (isActive) {
            return UserStatus.active;
        } else {
            return UserStatus.disabled;
        }
    }

    private SearchRestriction convertCriteria(UserSearchCriteria criteria) {
        List<SearchRestriction> restrictions = new ArrayList<>();
        if (StringUtils.isNotBlank(criteria.getEmail())) {
            restrictions.add(Restriction.on(UserTermKeys.EMAIL).exactlyMatching(criteria.getEmail()));
        }
        if (StringUtils.isNotBlank(criteria.getUserId())) {
            restrictions.add(Restriction.on(UserTermKeys.USERNAME).exactlyMatching(criteria.getUserId()));
        }
        restrictions.add(Restriction.on(UserTermKeys.ACTIVE).exactlyMatching(Boolean.TRUE));
        return Combine.allOf(restrictions);
    }

}

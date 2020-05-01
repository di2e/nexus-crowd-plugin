package org.sonatype.nexus.plugins.crowd.client;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.rest.service.RestCrowdClient;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.CrowdClient;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class CachingCrowdClient extends RestCrowdClient implements CrowdClient {

    private final CacheManager ehCacheManager;
    private static final String USERNAME_PASSWORD_CACHE = "com.atlassian.crowd.integration-auth-username";
    private static final String TOKEN_CACHE = "com.atlassian.crowd.integration-auth-token";
    private static final String GROUP_CACHE = "com.atlassian.crowd.integration-group";

    // default TTL of 5 minutes
    private static final long DEFAULT_TTL = 300;

    private static final Logger logger = LoggerFactory.getLogger(CachingCrowdClient.class);

    public CachingCrowdClient(ClientProperties clientProperties) {
        super(clientProperties);
        this.ehCacheManager = CacheManager.getInstance();

        if (!ehCacheManager.cacheExists(USERNAME_PASSWORD_CACHE)) {
            Cache newCache = new Cache(USERNAME_PASSWORD_CACHE, 10000, false, false, DEFAULT_TTL, DEFAULT_TTL);
            ehCacheManager.addCache(newCache);
        }
        if (!ehCacheManager.cacheExists(TOKEN_CACHE)) {
            Cache newCache = new Cache(TOKEN_CACHE, 10000, false, false, DEFAULT_TTL, DEFAULT_TTL);
            ehCacheManager.addCache(newCache);
        }
        if (!ehCacheManager.cacheExists(GROUP_CACHE)) {
            Cache newCache = new Cache(GROUP_CACHE, 10000, false, false, DEFAULT_TTL, DEFAULT_TTL);
            ehCacheManager.addCache(newCache);
        }
    }

    @Override
    public User authenticateUser(String username, String password) throws UserNotFoundException, InactiveAccountException, ExpiredCredentialException, ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        User user;
        Element element = getUsernamePasswordCache().get(username + "#" + password);
        if (element != null) {
            user = (User) element.getObjectValue();
            logger.debug("User {} successfully authenticated using cached credentials.", user.getName());
        } else {
            user = super.authenticateUser(username, password);
            getUsernamePasswordCache().put(new Element(username + "#" + password, user));
            logger.debug("User {} successfully authenticated and added to authentication cache.", user.getName());
        }
        return user;
    }

    @Override
    public User findUserFromSSOToken(String token) throws InvalidTokenException, ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        User user;
        Element element = getTokenCache().get(token);
        if (element != null) {
            user = (User) element.getObjectValue();
            logger.debug("User {} successfully authenticated using cached SSO credentials.", user.getName());
        } else {
            user = super.findUserFromSSOToken(token);
            getTokenCache().put(new Element(token, user));
            logger.debug("User {} successfully authenticated using SSO token and added to token cache.", user.getName());
        }
        return user;
    }

    @Override
    public List<String> getNamesOfGroupsForNestedUser(String userName, int startIndex, int maxResults) throws UserNotFoundException, ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        List<String> groups;
        Element element = getGroupCache().get(userName);
        if (element != null) {
            groups = (List<String>) element.getObjectValue();
            logger.debug("Retrieved cached groups for user ({})", userName);
        } else {
            groups = super.getNamesOfGroupsForNestedUser(userName, startIndex, maxResults);
            getGroupCache().put(new Element(userName, groups));
            logger.debug("Retrieved groups for user ({}), caching internally.", userName);
        }
        return groups;
    }

    private Cache getUsernamePasswordCache() {
        return ehCacheManager.getCache(USERNAME_PASSWORD_CACHE);
    }

    private Cache getTokenCache() {
        return ehCacheManager.getCache(TOKEN_CACHE);
    }

    private Cache getGroupCache() {
        return ehCacheManager.getCache(GROUP_CACHE);
    }
}

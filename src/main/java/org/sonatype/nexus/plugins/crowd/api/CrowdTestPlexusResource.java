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
package org.sonatype.nexus.plugins.crowd.api;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.restlet.Context;
import org.restlet.data.Request;
import org.restlet.data.Response;
import org.restlet.data.Status;
import org.restlet.resource.ResourceException;
import org.restlet.resource.Variant;
import org.sonatype.nexus.plugins.crowd.client.CrowdClientHolder;
import org.sonatype.nexus.rest.PathProtectionDescriptorBuilder;
import org.sonatype.plexus.rest.resource.AbstractPlexusResource;
import org.sonatype.plexus.rest.resource.PathProtectionDescriptor;
import org.sonatype.plexus.rest.resource.PlexusResource;

/**
 * Intent of this class is to enable an admin to easily test if the Crowd
 * connection is working <b>without</b> enabling the Realm.
 * 
 * @author Justin Edelson
 * @author Issa Gorissen
 */
@Singleton
@Typed(PlexusResource.class)
@Named("CrowdTestPlexusResource")
@Produces(MediaType.APPLICATION_XML)
@Path(CrowdTestPlexusResource.RESOURCE_URI)
public class CrowdTestPlexusResource extends AbstractPlexusResource {
	public static final String RESOURCE_URI = "/crowd/test";

    @Inject
    private CrowdClientHolder crowdClientHolder;

    @Override
    public Object getPayloadInstance() {
        return null;
    }

    @Override
    public PathProtectionDescriptor getResourceProtection() {
    	return new PathProtectionDescriptorBuilder().path(RESOURCE_URI).anon().build();
    }

    @Override
    public String getResourceUri() {
        return RESOURCE_URI;
    }

    @Override
    @GET
    public Object get(Context context, Request request, Response response, Variant variant)
            throws ResourceException {
        try {
            crowdClientHolder.getCrowdClient().getCookieConfiguration();
            return "<status>OK</status>";
        } catch (Exception e) {
            throw new ResourceException(Status.SERVER_ERROR_SERVICE_UNAVAILABLE,
                    "Unable to authenticate. Check configuration.", e);
        }
    }
}

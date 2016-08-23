/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aaf.vhr.idp.http;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.context.ProfileRequestContext;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;

import aaf.vhr.idp.VhrSessionValidator;

/**
 * Extracts authentication information from the request and returns it via the IdP's external authentication
 * interface.
 *
 * <p>Common usage allows for extraction of REMOTE_USER or a username from request attributes or headers.</p>
 *
 * <p>More advanced features include the ability to directly consume a {@link Subject} from a request
 * attribute (in which case it is returned sight unseen directly to the IdP as the external result)
 * and the ability to check a header for strings containing authentication method identifiers which
 * can be mapped back into custom {@link Principal} objects (in which case they are attached to a newly
 * constructed {@link Subject} to return).</p>
 */
public class VhrRemoteUserAuthServlet extends HttpServlet {

    /** Serial UID. */
    private static final long serialVersionUID = -7128277314402803944L;

    /** Init parameter controlling whether to check for REMOTE_USER. */
    @Nonnull @NotEmpty private static final String CHECK_REMOTE_USER_PARAM = "checkRemoteUser";

    /** Init parameter controlling what attributes to check. */
    @Nonnull @NotEmpty private static final String CHECK_ATTRIBUTES_PARAM = "checkAttributes";

    /** Init parameter controlling what headers to check. */
    @Nonnull @NotEmpty private static final String CHECK_HEADERS_PARAM = "checkHeaders";

    /** Init parameter identifying an attribute to check for a Subject. */
    @Nonnull @NotEmpty private static final String SUBJECT_ATTRIBUTE_PARAM = "subjectAttribute";

    /** Init parameter identifying a header to check for one or more authentication method strings. */
    @Nonnull @NotEmpty private static final String AUTHN_METHOD_HEADER_PARAM = "authnMethodHeader";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(VhrRemoteUserAuthServlet.class);

    /** Whether to check REMOTE_USER for an identity. Defaults to true. */
    private boolean checkRemoteUser;

    /** List of request attributes to check for an identity. */
    @Nonnull @NonnullElements private Collection<String> checkAttributes;

    /** List of request headers to check for an identity. */
    @Nonnull @NonnullElements private Collection<String> checkHeaders;

    /** Request attribute to check for a {@link Subject}. */
    @Nullable @NotEmpty private String subjectAttribute;

    /** Header to check for authentication method strings. */
    @Nullable @NotEmpty private String authnMethodHeader;

    // VHR-specific attributes
    final String SSO_COOKIE_NAME = "_vh_l1";

    final String EXTERNAL_AUTH_KEY_ATTR_NAME = "external_auth_session_key";

    private String vhrLoginEndpoint;
    private VhrSessionValidator vhrSessionValidator;

    /** Constructor. */
    public VhrRemoteUserAuthServlet() {
        checkRemoteUser = true;
        checkAttributes = Collections.emptyList();
        checkHeaders = Collections.emptyList();
    }

    /**
     * Set whether to check REMOTE_USER for an identity.
     *
     * @param flag value to set
     */
    public void setCheckRemoteUser(final boolean flag) {
        checkRemoteUser = flag;
    }

    /**
     * Set the list of request attributes to check for an identity.
     *
     * @param attributes    list of request attributes to check
     */
    public void setCheckAttributes(@Nonnull @NonnullElements final Collection<String> attributes) {
        checkAttributes = new ArrayList<>(Collections2.filter(attributes, Predicates.notNull()));
    }

    /**
     * Set the list of request headers to check for an identity.
     *
     * @param headers list of request headers to check
     */
    public void setCheckHeaders(@Nonnull @NonnullElements final Collection<String> headers) {
        checkHeaders = new ArrayList<>(Collections2.filter(headers, Predicates.notNull()));
    }

    /**
     * Set the name of a request attribute to check for a {@link Subject}.
     *
     * @param attribute request attribute name
     */
    public void setSubjectAttribute(@Nullable @NotEmpty final String attribute) {
        subjectAttribute = StringSupport.trimOrNull(attribute);
    }

    /**
     * Set the name of a request header to check for authentication method strings.
     *
     * @param header request header name
     */
    public void setAuthnMethodHeader(@Nullable @NotEmpty final String header) {
        authnMethodHeader = StringSupport.trimOrNull(header);
    }

// Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        String param = config.getInitParameter(CHECK_REMOTE_USER_PARAM);
        if (param != null) {
            checkRemoteUser = Boolean.parseBoolean(param);
        }

        param = config.getInitParameter(CHECK_ATTRIBUTES_PARAM);
        if (param != null) {
            final String[] attrs = param.split(" ");
            if (attrs != null) {
                checkAttributes = StringSupport.normalizeStringCollection(Arrays.asList(attrs));
            }
        }

        param = config.getInitParameter(CHECK_HEADERS_PARAM);
        if (param != null) {
            final String[] headers = param.split(" ");
            if (headers != null) {
                checkHeaders = StringSupport.normalizeStringCollection(Arrays.asList(headers));
            }
        }

        param = config.getInitParameter(SUBJECT_ATTRIBUTE_PARAM);
        if (param != null) {
            setSubjectAttribute(param);
        }

        param = config.getInitParameter(AUTHN_METHOD_HEADER_PARAM);
        if (param != null) {
            setAuthnMethodHeader(param);
        }

        log.info("RemoteUserAuthServlet {} process REMOTE_USER, along with attributes {} and headers {}",
                new Object[] {checkRemoteUser ? "will" : "will not", checkAttributes, checkHeaders,});
        if (subjectAttribute != null) {
            log.info("RemoteUserAuthServlet will check for a javax.security.auth.Subject in attribute: {}",
                    subjectAttribute);
        }
        if (authnMethodHeader != null) {
            log.info("RemoteUserAuthServlet will check for authentication methods in header: {}", authnMethodHeader);
        }

        // VHR-specific initalization
        vhrLoginEndpoint = config.getInitParameter("loginEndpoint");
        String apiServer = config.getInitParameter("apiServer");
        String apiEndpoint = config.getInitParameter("apiEndpoint");
        String apiToken = config.getInitParameter("apiToken");
        String apiSecret = config.getInitParameter("apiSecret");
        String requestingHost = config.getInitParameter("requestingHost");

        vhrSessionValidator = new VhrSessionValidator(apiServer, apiEndpoint, apiToken, apiSecret, requestingHost);

    }

// Checkstyle: MethodLength OFF
    /** {@inheritDoc} */
    @Override
    protected void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {

        try {
            String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
            // TODO: try avoiding this call if we are to load a key instead

            // Check for a Subject, in which case the rest is skipped.
            if (subjectAttribute != null) {
                final Object subject = httpRequest.getAttribute(subjectAttribute);
                if (subject != null && subject instanceof Subject) {
                    log.debug("Java Subject extracted from attribute {}: {}", subjectAttribute, subject);
                    httpRequest.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                    return;
                } else {
                    log.info("Java Subject not found in attribute {}, subjectAttribute");
                }
            }

            String username = null;

            if (checkRemoteUser) {
                username = httpRequest.getRemoteUser();
                if (username != null && !username.isEmpty()) {
                    log.debug("User identity extracted from REMOTE_USER: {}", username);
                }
            }

            if (username == null) {
                for (final String s : checkAttributes) {
                    final Object attr = httpRequest.getAttribute(s);
                    if (attr != null && !attr.toString().isEmpty()) {
                        username = attr.toString();
                        log.debug("User identity extracted from attribute {}: {}", s, username);
                        break;
                    }
                }
            }

            if (username == null) {
                for (final String s : checkHeaders) {
                    username = httpRequest.getHeader(s);
                    if (username != null && !username.isEmpty()) {
                        log.debug("User identity extracted from header {}: {}", s, username);
                        break;
                    }
                }
            }

            if (username != null) {
                log.info("Found username {} already set by previous filter or webserver module. Disabling VHR authentication process.", httpRequest.getRemoteUser());
            } else {
                log.debug("No username found so far (correct). Starting VHR Authentication...");

                URLCodec codec = new URLCodec();
                String relyingParty = (String)httpRequest.getAttribute("relyingParty");

                // Attempt to locate VHR SessionID
                String vhrSessionID = null;
                Cookie[] cookies = httpRequest.getCookies();
                for(Cookie cookie : cookies) {
                        if(cookie.getName().equals(SSO_COOKIE_NAME)) {
                                vhrSessionID = cookie.getValue();
                                break;
                        }
                }

                if(vhrSessionID == null) {
                        log.info("No vhrSessionID found from {}. Directing to VHR authentication process.", httpRequest.getRemoteHost());
                        log.debug ("Relying party which initiated the SSO request was: {}", relyingParty);
                        // NEW: save session *key*
                        HttpSession hs = httpRequest.getSession(true);
                        hs.setAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME, key);


                        try {
                                httpResponse.sendRedirect(String.format(vhrLoginEndpoint, codec.encode(httpRequest.getRequestURL().toString()+(httpRequest.getQueryString()!=null ? '?' + httpRequest.getQueryString() : "")), codec.encode(relyingParty)));
                        } catch (EncoderException e) {
                                log.error ("Could not encode VHR redirect params");
                                throw new IOException(e);
                        }
                        return; // we issued a redirect - return now
                } else {
                        // NEW: load session *key*
                        HttpSession hs = httpRequest.getSession(true);
                        if (hs != null) {
                           String old_key = key; // use if something else fails
                           key = (String)hs.getAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME);
                        };
                }
                // TODO: check login: we are using the right key when retrying...

                log.info("Found vhrSessionID from {}. Establishing validity.", httpRequest.getRemoteHost());
                username = vhrSessionValidator.validateSession(vhrSessionID);

                if(username != null) {
                        log.info("Established validity for {}, setting username to {}", httpRequest.getRemoteHost(), username);
                } else try {
                        log.info("Failed to establish validity for {} vhrSessionID.", httpRequest.getRemoteHost());
                        // NEW: save session *key*
                        HttpSession hs = httpRequest.getSession(true);
                        hs.setAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME, key);

                        httpResponse.sendRedirect(String.format(vhrLoginEndpoint, codec.encode(httpRequest.getRequestURL().toString()+(httpRequest.getQueryString()!=null ? '?' + httpRequest.getQueryString() : "")), codec.encode(relyingParty)));
                        return; // we issued a redirect - return now
                } catch (EncoderException e) {
                        log.error ("Could not encode VHR redirect params after failing to establish validity");
                        throw new IOException(e);
                }

            }

            if (username == null) {
                log.info("User identity not found in request");
                ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                return;
            }

            if (authnMethodHeader != null) {
                // Check for authentication methods.
                final Enumeration<String> methods = httpRequest.getHeaders(authnMethodHeader);
                if (methods != null && methods.hasMoreElements()) {
                    final AuthenticationFlowDescriptor authnFlow = getAuthenticationFlowDescriptor(key, httpRequest);
                    if (authnFlow != null) {
                        final Subject subject = new Subject();
                        subject.getPrincipals().add(new UsernamePrincipal(username));

                        while (methods.hasMoreElements()) {
                            final String method = methods.nextElement();
                            if (!Strings.isNullOrEmpty(method)) {
                                final Principal p = getPrincipal(authnFlow, method);
                                if (p != null) {
                                    log.debug("Successfully processed authentication method from header {}: {}",
                                            authnMethodHeader, method);
                                    subject.getPrincipals().add(p);
                                } else {
                                    log.warn("Unable to locate a suitable Principal for authentication method " +
                                            "from header {}: {}", authnMethodHeader, method);
                                }
                            }
                        }

                        httpRequest.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
                        ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                        return;
                    } else {
                        log.error("Unable to locate AuthenticationFlowDescriptor, can't process "
                                + "authentication methods from header");
                    }
                }

                httpRequest.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, username);
            } else {
                httpRequest.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, username);
            }

            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);

        } catch (final ExternalAuthenticationException e) {
            throw new ServletException("Error processing external authentication request", e);
        }
    }
// Checkstyle: CyclomaticComplexity|MethodLength ON

    /**
     * Get the executing {@link AuthenticationFlowDescriptor}.
     *
     * @param key external authentication key
     * @param httpRequest servlet request
     *
     * @return active descriptor, or null
     * @throws ExternalAuthenticationException  if unable to access the profile context
     */
    @Nullable public AuthenticationFlowDescriptor getAuthenticationFlowDescriptor(@Nonnull @NotEmpty final String key,
            @Nonnull final HttpServletRequest httpRequest) throws ExternalAuthenticationException {

        final ProfileRequestContext prc =
                ExternalAuthentication.getProfileRequestContext(key, httpRequest);
        final AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class);
        return (authnCtx != null) ? authnCtx.getAttemptedFlow() : null;
    }

    /**
     * Locate a custom {@link Principal} matching a string, supported by the flow descriptor.
     *
     * @param descriptor flow descriptor
     * @param method method string
     *
     * @return a custom {@link Principal} or null
     */
    @Nullable public Principal getPrincipal(@Nonnull final AuthenticationFlowDescriptor descriptor,
            @Nonnull @NotEmpty final String method) {

        for (final Principal p :descriptor.getSupportedPrincipals()) {
            if (p.getName().equals(method)) {
                return p;
            }
        }

        return null;
    }

}

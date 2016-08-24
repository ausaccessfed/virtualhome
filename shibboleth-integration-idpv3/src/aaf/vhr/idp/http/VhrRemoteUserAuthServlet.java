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

import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.consent.context.ConsentManagementContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import aaf.vhr.idp.VhrSessionValidator;

/**
 * Authenticate a user against the VHR.
 */
public class VhrRemoteUserAuthServlet extends HttpServlet {

    /** Serial UID. */
    private static final long serialVersionUID = -4936410983928392293L;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(VhrRemoteUserAuthServlet.class);

    // VHR-specific attributes
    final String SSO_COOKIE_NAME = "_vh_l1";

    final String EXTERNAL_AUTH_KEY_ATTR_NAME = "external_auth_session_key";

    private String vhrLoginEndpoint;
    private VhrSessionValidator vhrSessionValidator;

// Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

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

            String username = null;

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
                        if (hs != null && hs.getAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME) != null ) {
                           String old_key = key; // use if something else fails
                           key = (String)hs.getAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME);
                           // remove the attribute from the session so that we do not attempt to reuse it...
                           hs.removeAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME);
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

            // check if consent revocation was requested
            // TODO: make the parameter name configurable (or define a constant)
            String consentRevocationParam = httpRequest.getParameter("uApprove.consent-revocation");
            if (consentRevocationParam != null) {
                // we should pass on the request for consent revocation
                final ProfileRequestContext prc =
                        ExternalAuthentication.getProfileRequestContext(key, httpRequest);
                final ConsentManagementContext consentCtx = prc.getSubcontext(ConsentManagementContext.class, true);
                log.debug("Consent revocation request received, setting revokeConsent in consentCtx");
                consentCtx.setRevokeConsent(consentRevocationParam.equalsIgnoreCase("true"));
            };

            httpRequest.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, username);

            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);

        } catch (final ExternalAuthenticationException e) {
            throw new ServletException("Error processing external authentication request", e);
        }
    }
// Checkstyle: CyclomaticComplexity|MethodLength ON

}

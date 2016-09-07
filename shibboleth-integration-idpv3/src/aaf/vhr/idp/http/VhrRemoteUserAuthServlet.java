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

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.consent.context.ConsentManagementContext;
import net.shibboleth.idp.ui.context.RelyingPartyUIContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
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

    final String EXTERNAL_AUTH_KEY_ATTR_NAME = "aaf.vhr.idp.http.VhrRemoteUserAuthServlet.externalAuthenticationSessionKey";
    final String IS_FORCE_AUTHN_ATTR_NAME = "aaf.vhr.idp.http.VhrRemoteUserAuthServlet.isForceAuthn";
    final String AUTHN_INIT_INSTANT_ATTR_NAME = "aaf.vhr.idp.http.VhrRemoteUserAuthServlet.authnInitInstant";
    final String REDIRECT_REQ_PARAM_NAME = "vhr.redir";

    private String vhrLoginEndpoint;
    private VhrSessionValidator vhrSessionValidator;

    /** Name of the request parameter that would indicate the user wants to revoke consent */
    private String consentRevocationParamName = "_shib_idp_revokeConsent";

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

        // Consent revocation parameter name: override default if set
        String crpn = config.getInitParameter("consentRevocationParamName");
        if (crpn != null) { consentRevocationParamName = crpn; };

        vhrSessionValidator = new VhrSessionValidator(apiServer, apiEndpoint, apiToken, apiSecret, requestingHost);

    }

// Checkstyle: MethodLength OFF
    /** {@inheritDoc} */
    @Override
    protected void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {

        try {
            // key to ExternalAuthentication session
            String key = null;
            boolean isVhrReturn = false;
            boolean isForceAuthn = false;
            DateTime authnStart = null; // when this authentication started at the IdP

            if (httpRequest.getParameter(REDIRECT_REQ_PARAM_NAME) != null) {
                // we have come back from the VHR
                isVhrReturn = true;
                HttpSession hs = httpRequest.getSession();
                if (hs != null && hs.getAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME) != null ) {
                   key = (String)hs.getAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME);
                   // remove the attribute from the session so that we do not attempt to reuse it...
                   hs.removeAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME);
                };

                if (hs != null && hs.getAttribute(AUTHN_INIT_INSTANT_ATTR_NAME) != null ) {
                   authnStart = (DateTime)hs.getAttribute(AUTHN_INIT_INSTANT_ATTR_NAME);
                   // remove the attribute from the session so that we do not attempt to reuse it...
                   hs.removeAttribute(AUTHN_INIT_INSTANT_ATTR_NAME);
                };

                if (hs != null && hs.getAttribute(IS_FORCE_AUTHN_ATTR_NAME) != null ) {
                   isForceAuthn = ((Boolean)hs.getAttribute(IS_FORCE_AUTHN_ATTR_NAME)).booleanValue();
                   // remove the attribute from the session so that we do not attempt to reuse it...
                   hs.removeAttribute(AUTHN_INIT_INSTANT_ATTR_NAME);
                };

            } else {
                // starting a new SSO request
                key = ExternalAuthentication.startExternalAuthentication(httpRequest);

                // check if forceAuthn is set
                Object forceAuthnAttr = httpRequest.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM);
                if ( forceAuthnAttr != null && forceAuthnAttr instanceof java.lang.Boolean) {
                    log.debug("Loading foceAuthn value");
                    isForceAuthn = ((Boolean)forceAuthnAttr).booleanValue();
                }

                // check if we can see when authentication was initiated
                final AuthenticationContext authCtx =
                        ExternalAuthentication.getProfileRequestContext(key, httpRequest).
                            getSubcontext(AuthenticationContext.class,false);
                if (authCtx != null) {
                    log.debug("Authentication initiation is {}", authCtx.getInitiationInstant());
                    authnStart = new DateTime(authCtx.getInitiationInstant(), DateTimeZone.UTC);
                    log.debug("AuthnStart is {}", authnStart);
                };

            };
            log.debug("forceAuthn is {}, authnStart is {}", isForceAuthn, authnStart);

            if (key == null) {
                log.error("No ExternalAuthentication sesssion key found");
                throw new ServletException("No ExternalAuthentication sesssion key found");
            };
            // we now have a key - either:
            // * we started new authentication
            // * or we have returned from VHR and loaded the key from the HttpSession

            String username = null;

            // We may have a cookie - either as part of return or from previous session
            // Attempt to locate VHR SessionID
            String vhrSessionID = null;
            Cookie[] cookies = httpRequest.getCookies();
            for(Cookie cookie : cookies) {
                if(cookie.getName().equals(SSO_COOKIE_NAME)) {
                    vhrSessionID = cookie.getValue();
                    break;
                }
            }

            if (vhrSessionID != null) {
                log.info("Found vhrSessionID from {}. Establishing validity.", httpRequest.getRemoteHost());
                username = vhrSessionValidator.validateSession(vhrSessionID, ( isForceAuthn ? authnStart : null));
            };

            // If we do not have a username yet (no Vhr session cookie or did not validate),
            // we redirect to VHR - but only if we are not returning from the VHR
            // Reason: (i) we do not want to loop and (ii) we do not have the full context otherwise initialized by
            // ExternalAuthentication.startExternalAuthentication()
            if ( username == null && !isVhrReturn ) {

                URLCodec codec = new URLCodec();
                String relyingParty = (String)httpRequest.getAttribute("relyingParty");
                String serviceName = "";

                log.info("No vhrSessionID found from {}. Directing to VHR authentication process.", httpRequest.getRemoteHost());
                log.debug("Relying party which initiated the SSO request was: {}", relyingParty);

                // try getting a RelyingPartyUIContext
                // we should pass on the request for consent revocation
                final ProfileRequestContext prc =
                        ExternalAuthentication.getProfileRequestContext(key, httpRequest);
                final RelyingPartyUIContext rpuiCtx = prc.getSubcontext(AuthenticationContext.class,true).
                        getSubcontext(RelyingPartyUIContext.class, false);
                if (rpuiCtx != null) {
                    serviceName = rpuiCtx.getServiceName();
                    log.debug("RelyingPartyUIContext received, ServiceName is {}", serviceName);
                };

                // save session *key*
                HttpSession hs = httpRequest.getSession(true);
                hs.setAttribute(EXTERNAL_AUTH_KEY_ATTR_NAME, key);
                hs.setAttribute(IS_FORCE_AUTHN_ATTR_NAME, new Boolean(isForceAuthn));
                hs.setAttribute(AUTHN_INIT_INSTANT_ATTR_NAME, authnStart);

                try {
                    httpResponse.sendRedirect(String.format(vhrLoginEndpoint, codec.encode(httpRequest.getRequestURL().toString()+"?"+REDIRECT_REQ_PARAM_NAME+"=true"), codec.encode(relyingParty), codec.encode(serviceName)));
                } catch (EncoderException e) {
                    log.error ("Could not encode VHR redirect params");
                    throw new IOException(e);
                }
                return; // we issued a redirect - return now
            };

            if (username == null) {
                log.warn("VirtualHome authentication failed: no username received");
                httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "VirtualHome authentication failed: no username received");
                ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                return;
            }

            // check if consent revocation was requested
            String consentRevocationParam = httpRequest.getParameter(consentRevocationParamName);
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

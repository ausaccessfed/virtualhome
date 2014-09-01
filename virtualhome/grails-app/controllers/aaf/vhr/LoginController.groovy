package aaf.vhr

import groovyx.net.http.*
import static groovyx.net.http.ContentType.JSON
import javax.servlet.http.Cookie
import java.net.URLEncoder

import aaf.base.identity.Role
import aaf.vhr.switchch.vho.DeprecatedSubject

import aaf.vhr.crypto.GoogleAuthenticator

class LoginController {

  static allowedMethods = [login: 'POST', verifytwostepcode:'POST']

  final String INVALID_USER = "aaf.vhr.LoginController.INVALID_USER"
  final String FAILED_USER = "aaf.vhr.LoginController.FAILED_USER"
  final String CURRENT_USER = "aaf.vhr.LoginController.CURRENT_USER"
  final String SSO_URL = "aaf.vhr.LoginController.SSO_URL"
  final String NEW_TOTP_KEY = "aaf.vhr.LoginController.NEW_TOTP_KEY"
  final String UAPPROVE_CONSENT_REVOKE = "aaf.vhr.LoginController.UAPPROVE_CONSENT_REVOKE"

  def loginService

  def index() {
    if(params.ssourl) {
      session.setAttribute(SSO_URL, params.ssourl)
    } else {
      if(!session.getAttribute(SSO_URL)) {
        log.error "SSO URL not stored for user session and not provided by name/value pair for ssourl, redirecting to oops"
        redirect action:"oops"
      }
    }

    if(session.getAttribute(INVALID_USER)) {
      log.debug "INVALID_USER is true indicating invalid username being supplied. Rendering default login screen."
      session.removeAttribute(INVALID_USER)
      return [loginError:true, requiresChallenge:false]
    }

    if(session.getAttribute(FAILED_USER)) {
      def managedSubjectInstance = ManagedSubject.get(session.getAttribute(FAILED_USER))
      if(managedSubjectInstance) {
        log.debug "FAILED_USER is set for $managedSubjectInstance indicating previous failure. Rendering default login screen."
        session.removeAttribute(FAILED_USER)
        return [loginError:true, requiresChallenge:managedSubjectInstance.requiresLoginCaptcha()]
      }
    }
  }

  def login(String username, String password) {
    def redirectURL = session.getAttribute(SSO_URL)
    if(!redirectURL) {
      log.error "No redirectURL set for login, redirecting to oops"
      redirect action: "oops"
      return
    }

    def managedSubjectInstance = ManagedSubject.findWhere(login: username, [lock:true])
    if(!managedSubjectInstance) {
      log.error "No ManagedSubject represented by $username"
      session.setAttribute(INVALID_USER, true)
      redirect action:"index"
      return
    }

    def validPassword = loginService.passwordLogin(managedSubjectInstance, password, request, session, params)

    if(!validPassword) {
      log.info "LoginService indicates failure for attempted login by $managedSubjectInstance"
      session.setAttribute(FAILED_USER, managedSubjectInstance.id)
      redirect action:"index"
      return
    }

    // if the login form had the uApprove checkbox checked, save it for later
    if (params.uApproveConsentRevocation) {
        session.setAttribute(UAPPROVE_CONSENT_REVOKE, params.uApproveConsentRevocation)
    }

    session.setAttribute(CURRENT_USER, managedSubjectInstance.id)
    if(managedSubjectInstance.enforceTwoStepLogin() && !managedSubjectInstance.isUsingTwoStepLogin()){
      // This account needs to be updated before they can login
      log.info("Due to local or group policy the account $managedSubjectInstance must enroll into 2-Step verification with their phone before continuing login.")

      redirect action:'setuptwostep'
      return
    }

    if(managedSubjectInstance.isUsingTwoStepLogin()) {
      def twoStepCookie = request.cookies.find { it.name == LoginService.TWOSTEP_COOKIE_NAME }
      if(!twoStepCookie || !managedSubjectInstance.hasEstablishedTwoStepLogin(twoStepCookie.value)) {
        // No existing 2 step login or existing session is invalid
        log.info "Requesting 2-Step verification for ${managedSubjectInstance} as valid existing 2-Step verification was not found."
        render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance])
        return
      }

      log.info("Existing two step session identifier ${twoStepCookie.value} is valid for ${managedSubjectInstance}.")
    }

    log.info("Verified that all supplied credentials for ${managedSubjectInstance} are valid, establishing session.")
    redirect url: establishSession(managedSubjectInstance)
  }

  def twosteplogin(long totp) {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow twosteplogin to function"
      response.sendError 403
      return
    }

    if(!loginService.twoStepLogin(managedSubjectInstance, totp, request, response)) {
      log.info "LoginService indicates twoStepLogin failure for attempted login by $managedSubjectInstance"
      render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance, loginError:true])
      return
    }

    log.info("Verified that 2Step code for ${managedSubjectInstance} is valid, establishing session.")
    redirect url: establishSession(managedSubjectInstance)
  }

  def setuptwostep() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow setuptwostep to function"
      response.sendError 403
      return
    }

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    [managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
  }

  def completesetuptwostep() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow completesetuptwostep to function"
      response.sendError 403
      return
    }

    def totpKey = GoogleAuthenticator.generateSecretKey()
    session.setAttribute(NEW_TOTP_KEY, totpKey)

    def totpURL = GoogleAuthenticator.getQRBarcodeURL(managedSubjectInstance.login,
                                                      request.serverName, totpKey,
                                                      managedSubjectInstance.encodedTwoStepIssuer)
    [managedSubjectInstance:managedSubjectInstance, totpURL:totpURL]
  }

  def verifytwostepcode(long totp) {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    def totpKey = session.getAttribute(NEW_TOTP_KEY)

    if(!managedSubjectInstance || !totpKey) {
      log.error "A valid session does not already exist to allow verifytwostepcode to function"
      response.sendError 403
      return
    }

    if(GoogleAuthenticator.checkCode(totpKey, totp, System.currentTimeMillis())) {
      managedSubjectInstance.totpKey = totpKey
      if(!managedSubjectInstance.save()) {
        log.error "Unable to persist totpKey for $managedSubjectInstance"
        response.sendError 500
        return
      }

      session.removeAttribute(NEW_TOTP_KEY)

      // Verify again just to record it in the cache.
      if (!loginService.twoStepLogin(managedSubjectInstance, totp, request, response)) {
        log.error "LoginService indicates twoStepLogin failure for attempted login by $managedSubjectInstance, but token had already been validated. User is enabling 2-step using a replayed token value!? This should never happen"
        response.sendError 500
        return
      }

      log.info("Verified that initial 2Step configuration for ${managedSubjectInstance} is valid, account is now fully enrolled in 2-Step verification. Establishing session.")
      redirect url: establishSession(managedSubjectInstance)
    } else {
      log.info "GoogleAuthenticator indicates twoStepLogin failure for attempted login by $managedSubjectInstance when verifying 2Step setup"

      def totpURL = GoogleAuthenticator.getQRBarcodeURL(managedSubjectInstance.login,
                                                        request.serverName, totpKey,
                                                        managedSubjectInstance.encodedTwoStepIssuer)
      render(view: "completesetuptwostep", model: [managedSubjectInstance:managedSubjectInstance, totpURL:totpURL, loginError:true])
      return
    }

  }

  def oops() {
  }

  def servicedetails(long id) {
    def http = new HTTPBuilder("https://manager.test.aaf.edu.au/federationregistry/api/v1/serviceproviders/$id")

     http.request(Method.GET, ContentType.JSON) {req ->
        contentType = 'application/json; charset=UTF-8'

        response.success = {resp, json ->
          log.info "Collected a total of ${json.serviceprovider} from Federation Registry"
          render(contentType:"text/json") { json }
        }
        response.failure = {resp ->
          log.error "Error requesting service provider details from Federation Registry"
          log.error resp
          log.error resp.statusLine

          response.sendError 500
        }
     }
  }

  private String establishSession(ManagedSubject managedSubjectInstance) {
    def redirectURL = session.getAttribute(SSO_URL)
    if(!redirectURL) {
      log.error "No redirectURL set for login, redirecting to oops"
      return createLink(action: 'oops')
    }
    // check for uApprove attribute release consent revocation checkbox
    if(session.getAttribute(UAPPROVE_CONSENT_REVOKE)) {
      redirectURL = redirectURL + (redirectURL.indexOf('?')>=0 ? "&" : "?" ) +
          "uApprove.consent-revocation=" + 
          URLEncoder.encode(session.getAttribute(UAPPROVE_CONSENT_REVOKE))
    }

    session.removeAttribute(CURRENT_USER)

    def sessionID = loginService.establishSession(managedSubjectInstance)
    log.info "Login by ${managedSubjectInstance} was completed successfully. Associated new VH > Shib API session verification id of ${sessionID}."

    // Setup SSO cookie for use with Shib IdP VHR filter
    int maxAge = grailsApplication.config.aaf.vhr.login.validity_period_minutes * 60
    Cookie cookie = new Cookie(LoginService.SSO_COOKIE_NAME, sessionID)
    cookie.maxAge = maxAge
    cookie.secure = grailsApplication.config.aaf.vhr.login.ssl_only_cookie
    cookie.path = grailsApplication.config.aaf.vhr.login.path
    response.addCookie(cookie)

    session.removeAttribute(INVALID_USER)
    session.removeAttribute(CURRENT_USER)
    session.removeAttribute(SSO_URL)

    redirectURL
  }
}

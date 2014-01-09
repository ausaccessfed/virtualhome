package aaf.vhr

import groovyx.net.http.*
import static groovyx.net.http.ContentType.JSON
import javax.servlet.http.Cookie

import aaf.vhr.switchch.vho.DeprecatedSubject

class LoginController {

  final String INVALID_USER = "aaf.vhr.LoginController.INVALID_USER"
  final String CURRENT_USER = "aaf.vhr.LoginController.CURRENT_USER"
  final String SSO_URL = "aaf.vhr.LoginController.SSO_URL"

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

    if(session.getAttribute(CURRENT_USER)) {
      def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
      if(managedSubjectInstance) {
        log.debug "CURRENT_USER is set indicating previous failure. Rendering default login screen."
        session.removeAttribute(CURRENT_USER)
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
      session.setAttribute(CURRENT_USER, managedSubjectInstance.id)
      redirect action:"index"
      return
    }

    if(managedSubjectInstance.enforceTwoStepLogin() && !managedSubjectInstance.isUsingTwoStepLogin()){
      // This account needs to be updated before they can login
      session.setAttribute(AccountController.CURRENT_USER, managedSubjectInstance.id)
      redirect controller:'account', action:'setuptwostep'
      return
    }

    if(managedSubjectInstance.isUsingTwoStepLogin()) {
      def twoStepCookie = request.cookies.find { it.name == LoginService.TWOSTEP_COOKIE_NAME }
      if(!twoStepCookie || !managedSubjectInstance.hasEstablishedTwoStepLogin(twoStepCookie.value)) {
        // No existing 2 step login or existing session is invalid
        log.info "Requesting 2-Step verification for ${managedSubjectInstance}"
        render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance])
        return
      }

      log.info("Existing two step session identifier ${twoStepCookie.value} is valid for ${managedSubjectInstance}.")
    }

    redirect url: establishSession(managedSubjectInstance)
  }

  def twosteplogin(long id, long totp) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(!managedSubjectInstance) {
      log.error "No ManagedSubject represented by $id in extendedlogin"
      session.setAttribute(INVALID_USER, true)
      redirect action:"index"
      return
    }

    if(!loginService.twoStepLogin(managedSubjectInstance, totp, request, response)) {
      log.info "LoginService indicates twoStepLogin failure for attempted login by $managedSubjectInstance"
      render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance, loginError:true])
      return
    }

    redirect url: establishSession(managedSubjectInstance)
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

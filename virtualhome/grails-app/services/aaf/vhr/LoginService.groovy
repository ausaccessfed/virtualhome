package aaf.vhr

import org.springframework.beans.factory.InitializingBean
import java.util.concurrent.TimeUnit
import com.google.common.cache.*

import javax.servlet.http.Cookie

import aaf.vhr.crypto.GoogleAuthenticator

class LoginService implements InitializingBean{

  static final String SSO_COOKIE_NAME = "_vh_l1"
  static final String TWOSTEP_COOKIE_NAME = "_vh_l2"

  boolean transactional = true
  def grailsApplication

  def recaptchaService
  def cryptoService

  int validityPeriod = 2  // Defaults to 2 minutes, override in config

  Cache<String, String> loginCache
  Cache<String, String> totpCache

  void afterPropertiesSet()  {
    if(grailsApplication.config.aaf.vhr.login.validity_period_minutes)
      validityPeriod = grailsApplication.config.aaf.vhr.login.validity_period_minutes

    //initialize the loginCache
    loginCache = CacheBuilder.newBuilder().
    expireAfterWrite(validityPeriod, TimeUnit.MINUTES).
    maximumSize(1000).
    build()

    totpCache = CacheBuilder.newBuilder().
    expireAfterWrite(validityPeriod * 3, TimeUnit.MINUTES).
    maximumSize(1000).
    build()
  }

  public String sessionRemoteUser(String sessionID) {
    loginCache.getIfPresent(sessionID)
  }

  public boolean passwordLogin(ManagedSubject managedSubjectInstance, String password, def request, def session, def params) {
    if(!managedSubjectInstance.canLogin()) {
      String reason = "User attempted login but account is disabled."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The ManagedSubject $managedSubjectInstance can not login at this time due to inactivty or locks"
      return false
    }

    if( managedSubjectInstance.requiresLoginCaptcha() && !recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
      String reason = "User provided invalid captcha data."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failCaptcha(reason, 'login_attempt', requestDetails, null)

      log.error "The recaptcha data supplied for ManagedSubject $managedSubjectInstance is not correct"
      return false
    }

    if(!cryptoService.verifyPasswordHash(password, managedSubjectInstance)) {
      String reason = "User provided an incorrect password."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The password supplied for ManagedSubject $managedSubjectInstance is not correct"
      return false
    }

    log.info "The password supplied for ManagedSubject $managedSubjectInstance was valid."

    String reason = "User provided correct password at login."
    String requestDetails = createRequestDetails(request)
    managedSubjectInstance.successfulLogin(reason, 'login_attempt', requestDetails, null)

    true
  }

  public boolean twoStepLogin(ManagedSubject managedSubjectInstance, long code, def request, def response) {
    if(!managedSubjectInstance.canLogin()) {
      String reason = "User attempted login but account is disabled (2-Step Verification)."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The ManagedSubject $managedSubjectInstance can not use login at this time due to inactivty or locks (2-Step Verification)."
      return false
    }

    // Make sure there is no replay attack going on
    def totpCacheKey = "$code:${managedSubjectInstance.login}"
    if(totpCache.getIfPresent(totpCacheKey)) {
      String reason = "Attempted to reuse code for 2-Step Verification."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The 2-Step Verification code supplied for ManagedSubject $managedSubjectInstance was previously used."
      return false
    }

    if(!GoogleAuthenticator.checkCode(managedSubjectInstance.totpKey, code, System.currentTimeMillis())) {
      String reason = "Invalid code for 2-Step Verification."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The 2-Step Verification code supplied for ManagedSubject $managedSubjectInstance is not correct or does not match the stored key."
      return false
    }

    def twoStepSession = managedSubjectInstance.establishTwoStepSession()

    log.info "The 2-Step verification code supplied for $managedSubjectInstance was valid."

    String reason = "Valid code for 2-Step verification. Assigned 90 day sessionID of ${twoStepSession.value}."
    String requestDetails = createRequestDetails(request)
    managedSubjectInstance.successfulLogin(reason, 'login_attempt', requestDetails, null)

    int maxAge = 90 * 24 * 60 * 60 // 90 days in seconds
    Cookie cookie = new Cookie(LoginService.TWOSTEP_COOKIE_NAME, twoStepSession.value)
    cookie.maxAge = maxAge
    cookie.secure = grailsApplication.config.aaf.vhr.login.ssl_only_cookie
    cookie.httpOnly = true
    cookie.path = grailsApplication.config.aaf.vhr.login.path
    response.addCookie(cookie)

    // Prevent replay - we don't really need the value for anything we're really just using the timeout
    totpCache.put(totpCacheKey, managedSubjectInstance.login)

    // Finally we cleanup old sessions
    log.info "Removing old 2-Step verification codes for $managedSubjectInstance."
    managedSubjectInstance.cleanupEstablishedTwoStepLogin()

    true
  }

  public String establishSession(ManagedSubject managedSubjectInstance) {
    def sessionID = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(64)
    loginCache.put(sessionID, managedSubjectInstance.login)

    sessionID
  }

  private String createRequestDetails(def request) {
"""User Agent: ${request.getHeader('User-Agent')}
Remote Host: ${request.getRemoteHost()}
Remote IP: ${request.getRemoteAddr()}
URI: ${request.requestURI}"""
  }
}

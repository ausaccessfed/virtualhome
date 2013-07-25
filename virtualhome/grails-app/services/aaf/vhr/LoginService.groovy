package aaf.vhr

import org.springframework.beans.factory.InitializingBean
import java.util.concurrent.TimeUnit
import com.google.common.cache.*

class LoginService implements InitializingBean{

  boolean transactional = true
  def grailsApplication

  def recaptchaService
  def cryptoService

  int validityPeriod = 2  // Defaults to 2 minutes, override in config

  Cache<String, String> loginCache

  void afterPropertiesSet()  {
    if(grailsApplication.config.aaf.vhr.login.validity_period_minutes)
      validityPeriod = grailsApplication.config.aaf.vhr.login.validity_period_minutes

    //initialize the loginCache
    loginCache = CacheBuilder.newBuilder().
    expireAfterWrite(validityPeriod, TimeUnit.MINUTES).
    maximumSize(1000).
    build()
  }

  public String sessionRemoteUser(String sessionID) {
    loginCache.getIfPresent(sessionID)
  }

  def webLogin(ManagedSubject managedSubjectInstance, String password, def request, def session, def params) {
    if(!managedSubjectInstance.canLogin()) {
      log.error "The ManagedSubject $managedSubjectInstance can not login at this time due to inactivty or locks"
      return [false, null]
    }

    if( managedSubjectInstance.requiresLoginCaptcha() && !recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
      String reason = "Recaptcha failed to verify user supplied captcha data as valid."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failCaptcha(reason, 'login_attempt', requestDetails, null)

      log.error "The recaptcha data supplied for ManagedSubject $managedSubjectInstance is not correct"
      return [false, null]
    }

    if(!cryptoService.verifyPasswordHash(password, managedSubjectInstance)) {
      String reason = "CryptoService failed to verify user supplied password as valid."
      String requestDetails = createRequestDetails(request)

      managedSubjectInstance.failLogin(reason, 'login_attempt', requestDetails, null)

      log.error "The password supplied for ManagedSubject $managedSubjectInstance is not correct"
      return [false, null]
    }

    log.info "The password supplied for ManagedSubject $managedSubjectInstance was valid. Creating sso cookie and redirecting to IdP."

    String reason = "User supplied valid username and verified password at login prompt."
    String requestDetails = createRequestDetails(request)
    managedSubjectInstance.successfulLogin(reason, 'login_attempt', requestDetails, null)

    def sessionID = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(64)
    loginCache.put(sessionID, managedSubjectInstance.login)

    return [true, sessionID]
  }

  private String createRequestDetails(def request) {
"""User Agent: ${request.getHeader('User-Agent')}
Remote Host: ${request.getRemoteHost()}
Remote IP: ${request.getRemoteAddr()}
URI: ${request.requestURI}"""
  }
}

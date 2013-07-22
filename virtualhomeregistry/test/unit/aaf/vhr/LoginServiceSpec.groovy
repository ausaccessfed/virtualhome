package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

@TestFor(aaf.vhr.LoginService)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject])
@Mock([Organization, Group, StateChange, ManagedSubject])
class LoginServiceSpec extends spock.lang.Specification {

  @Shared 
  def ms

  def recaptchaService
  def cryptoService

  def setup() {
    recaptchaService = Mock(com.megatome.grails.RecaptchaService)
    service.recaptchaService = recaptchaService

    cryptoService = Mock(aaf.vhr.CryptoService)
    service.cryptoService = cryptoService

    service.afterPropertiesSet()
    ms = ManagedSubject.build(hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')

    service.loginCache.invalidateAll()
  }

  def 'ensure content is stored in loginCache'() {
    when:
    service.loginCache.put('abcd1234', 'testuser')

    then:
    service.loginCache.getIfPresent('abcd1234') == 'testuser'
  }

  def 'get stored remote_user value'() {
    when:
    service.loginCache.put('abcd1234', remote_user)

    then:
    service.sessionRemoteUser(session) == expected_remote_user

    where:
    session << ['abcd1234', 'abcd123']
    remote_user << [ms.login, ms.login]
    expected_remote_user << [ms.login, null]
  }

  def 'ManagedSubject that cant login returns false'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]
    ms.active = false

    when:
    def (outcome, sessionID) = service.webLogin(ms, 'password', request, session, params)

    then:
    !outcome
    sessionID == null
  }

  def 'managedSubject that requires captcha must input one'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]
    ms.failedLogins = 3
    ms.active = true
    ms.organization.active = true

    expect:
    ms.requiresLoginCaptcha()

    when:
    def (outcome, sessionID) = service.webLogin(ms, 'password', request, session, params)

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> false

    !outcome
    sessionID == null
  }

  def 'an invalid password fails authentication'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true

    expect:
    ms.stateChanges == null
    service.loginCache.size() == 0

    when:
    def (outcome, sessionID) = service.webLogin(ms, 'password', request, session, params)

    then:
    1 * cryptoService.verifyPasswordHash(_,_,) >> false

    !outcome
    sessionID == null
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "CryptoService failed to verify user supplied password as valid."
    service.loginCache.size() == 0
  }

  def 'a valid password passes authentication'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true

    expect:
    ms.stateChanges == null
    service.loginCache.size() == 0

    when:
    def (outcome, sessionID) = service.webLogin(ms, 'password', request, session, params)

    then:
    1 * cryptoService.verifyPasswordHash(_,_,) >> true

    outcome
    sessionID.size() == 64
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User supplied valid username and verified password at login prompt."
    service.loginCache.size() == 1
  }

}

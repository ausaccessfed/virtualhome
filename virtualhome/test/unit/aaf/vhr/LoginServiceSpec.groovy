package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.crypto.GoogleAuthenticator

import org.springframework.mock.web.*

import groovy.time.TimeCategory

@TestFor(aaf.vhr.LoginService)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject])
@Mock([Organization, Group, StateChange, ManagedSubject, TwoStepSession])
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
    ms.twoStepSessions = []
    ms.metaClass.addToTwoStepSessions = {TwoStepSession session -> ms.twoStepSessions.add(session)}

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
    def outcome = service.passwordLogin(ms, 'password', request, session, params)

    then:
    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User attempted login but account is disabled."
  }

  def 'managedSubject that requires captcha and provides one gets it checked'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = ['g-recaptcha-response':'response']
    ms.failedLogins = 3
    ms.active = true
    ms.organization.active = true

    expect:
    ms.requiresLoginCaptcha()

    when:
    def outcome = service.passwordLogin(ms, 'password', request, session, params)

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> false

    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User provided invalid captcha data."
    service.loginCache.size() == 0
  }

  def 'managedSubject that requires captcha and does not provide one fails without verifying captcha'() {
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
    def outcome = service.passwordLogin(ms, 'password', request, session, params)

    then:
    0 * recaptchaService.verifyAnswer(_,_,_) >> false

    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User provided invalid captcha data."
    service.loginCache.size() == 0
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
    def outcome = service.passwordLogin(ms, 'password', request, session, params)

    then:
    1 * cryptoService.verifyPasswordHash(_,_,) >> false

    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User provided an incorrect password."
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
    def outcome = service.passwordLogin(ms, 'password', request, session, params)

    then:
    1 * cryptoService.verifyPasswordHash(_,_,) >> true

    outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User provided correct password at login."
    service.loginCache.size() == 0
  }

  def 'session identifier is established'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true

    expect:
    service.loginCache.size() == 0

    when:
    def sessionID = service.establishSession(ms)

    then:
    sessionID.size() == 64
    service.loginCache.size() == 1
  }

  def 'ManagedSubject that cant login returns false for twoStepLogin'() {
    setup:
    def request = Mock(javax.servlet.http.HttpServletRequest)
    def response = Mock(javax.servlet.http.HttpServletResponse)
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]
    ms.active = false

    when:
    def outcome = service.twoStepLogin(ms, 1234, request, response)

    then:
    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "User attempted login but account is disabled (2-Step Verification)."
  }

  def 'Incorrect two step code returns false'() {
    setup:
    def request = new MockHttpServletRequest()
    def response = new MockHttpServletResponse()
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> false }

    when:
    def outcome = service.twoStepLogin(ms, 1234, request, response)

    then:
    !outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason == "Invalid code for 2-Step Verification."

    response.cookies.size() == 0
  }

  def 'Correct two step code sets up 90 day session, cleans up old sessions and returns true'() {
    setup:
    def request = new MockHttpServletRequest()
    def response = new MockHttpServletResponse()
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true

    ms.twoStepSessions = [new TwoStepSession(value:'1234abcd', expiry: use(TimeCategory) {91.days.ago}), new TwoStepSession(value:'1234abcd', expiry: use(TimeCategory) {100.days.ago})]
    ms.save()

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> code == 1234 }

    expect:
    TwoStepSession.count() == 2

    when:
    def outcome = service.twoStepLogin(ms, 1234, request, response)

    then:
    outcome
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].category == 'login_attempt'
    ms.stateChanges.toArray()[0].reason.startsWith "Valid code for 2-Step verification. Assigned 90 day sessionID of"

    TwoStepSession.count() == 1   // Two old sessions removed, 1 new session present

    response.cookies.size() == 1
    response.cookies[0].maxAge == 90 * 24 * 60 * 60 // 90 days in seconds
    response.cookies[0].secure == response.cookies[0].secure
  }

  def 'Correct two step code that was used previously is rejected as potential MIIM'() {
    setup:
    def request = new MockHttpServletRequest()
    def response = new MockHttpServletResponse()
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true
    ms.save()

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> code == 1234 }

    expect:
    TwoStepSession.count() == 0

    when:
    service.twoStepLogin(ms, 1234, request, response)
    response.reset()
    def outcome = service.twoStepLogin(ms, 1234, request, response)

    then:
    !outcome
    ms.stateChanges.toArray()[1].category == 'login_attempt'
    ms.stateChanges.toArray()[1].reason.startsWith "Attempted to reuse code for 2-Step Verification."

    TwoStepSession.count() == 1   // Only 1st session establishment was successful.
    response.cookies.size() == 0
  }

  def 'Correct two step code that was used previously is rejected as potential MIIM but subsquent refreshed code is ok'() {
    setup:
    def request = new MockHttpServletRequest()
    def response = new MockHttpServletResponse()
    def session = Mock(javax.servlet.http.HttpSession)
    def params = [:]

    ms.failedLogins = 0
    ms.active = true
    ms.organization.active = true
    ms.save()

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> code == 1234 || code == 5678 }

    expect:
    TwoStepSession.count() == 0

    when:
    service.twoStepLogin(ms, 1234, request, response)
    response.reset()
    def miim = service.twoStepLogin(ms, 1234, request, response)
    response.reset()
    def outcome = service.twoStepLogin(ms, 5678, request, response)

    then:
    !miim
    outcome
    ms.stateChanges.toArray()[1].category == 'login_attempt'
    ms.stateChanges.toArray()[1].reason.startsWith "Attempted to reuse code for 2-Step Verification."
    ms.stateChanges.toArray()[2].category == 'login_attempt'
    ms.stateChanges.toArray()[2].reason.startsWith "Valid code for 2-Step verification. Assigned 90 day sessionID of"

    TwoStepSession.count() == 2   // 1st and 3rd session establishment was successful.
    response.cookies.size() == 1
  }

}

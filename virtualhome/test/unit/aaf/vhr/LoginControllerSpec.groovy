package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import aaf.base.identity.*
import aaf.vhr.switchch.vho.DeprecatedSubject

import javax.servlet.http.Cookie

import groovy.time.TimeCategory

import aaf.vhr.crypto.GoogleAuthenticator

@TestFor(aaf.vhr.LoginController)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject,aaf.vhr.switchch.vho.DeprecatedSubject])
@Mock([Organization, Group, ManagedSubject, TwoStepSession])
class LoginControllerSpec extends spock.lang.Specification {

  def "index errors if no sso url provided in request or session"() {
    when:
    controller.index()

    then:
    response.redirectedUrl == "/login/oops"
  }

  def "index success if ssourl provided in request"() {
    setup:
    params.ssourl = "http://test.com"

    when:
    def model = controller.index()

    then:
    response.status == 200
  }

  def "index success if ssourl provided in session"() {
    setup:
    session.setAttribute(controller.SSO_URL, "http://test.com")

    when:
    def model = controller.index()

    then:
    response.status == 200
  }

  def "invalid user sets loginError"() {
    setup:
    session.setAttribute(controller.SSO_URL, "http://test.com")
    session.setAttribute(controller.INVALID_USER, true)
  
    when:
    def model = controller.index()

    then:
    response.status == 200
    session.getAttribute(controller.INVALID_USER) == null
    model.loginError
    !model.requiresChallenge
  }

  def "failed user sets loginError"() {
    setup:
    def ms = ManagedSubject.build()

    session.setAttribute(controller.SSO_URL, "http://test.com")
    session.setAttribute(controller.FAILED_USER, ms.id)
  
    when:
    def model = controller.index()

    then:
    response.status == 200
    session.getAttribute(controller.FAILED_USER) == null
    model.loginError
    !model.requiresChallenge
  }

  def "login without valid managedSubject sets INVALID_USER"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    session.getAttribute(controller.INVALID_USER) == null

    when:
    controller.login('username', 'password')

    then:
    session.getAttribute(controller.INVALID_USER) == true
    response.redirectedUrl == "/login/index"
  }

  def "failed login redirects to index"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> false
    response.redirectedUrl == "/login/index"
    session.getAttribute(controller.FAILED_USER) == ms.id
  }

  def "successful login sets cookie and if set redirects to IdP login ssourl"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = true
    
    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
    response.cookies[0].maxAge == 1 * 60
    response.cookies[0].secure
  }

  def "successful login without redirectURL redirects to oops"() {
    setup:
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    response.redirectedUrl == "/login/oops"
    response.cookies.size() == 0
  }

  def "successful login sets insecure cookie and redirects to IdP login ssourl"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
    response.cookies[0].maxAge == 1 * 60
    !response.cookies[0].secure
  }

  def "successful login with uApprove param sets uApprove session variable and redirects to IdP with uApprove param"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    params.uApproveConsentRevocation = "true"
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn?uApprove.consent-revocation=true"
    response.cookies[0].maxAge == 1 * 60
    !response.cookies[0].secure
    session.getAttribute(controller.UAPPROVE_CONSENT_REVOKE) == "true"
  }

  def "successful login of account requiring totp with existing, valid, session cookie redirects to IdP loginssourl"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0, totpKey:'DPS6XA5YWTZFQ4FI')
    ms.organization.active = true

    def twoStepSession = new TwoStepSession()
    twoStepSession.populate()
    ms.twoStepSessions = [twoStepSession]

    Cookie cookie = new Cookie("_vh_l2", twoStepSession.value)
    request.cookies = [cookie]

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.cookies.size() == 1
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
  }

  def "successful login of account requiring totp with existing, valid but expired, session cookie renders code entry"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0, totpKey:'DPS6XA5YWTZFQ4FI')
    ms.organization.active = true

    def twoStepSession = new TwoStepSession()
    use (TimeCategory) {
      twoStepSession.populate()
      twoStepSession.expiry = 91.days.ago
      ms.twoStepSessions = [twoStepSession]
    }

    Cookie cookie = new Cookie("_vh_l2", twoStepSession.value)
    request.cookies = [cookie]

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.cookies.size() == 0
    response.redirectedUrl != "https://idp.test.com/shibboleth-idp/authn"
  }

  def "successful login of account requiring totp renders code entry"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0, totpKey:'DPS6XA5YWTZFQ4FI')
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.cookies.size() == 0
    response.redirectedUrl != "https://idp.test.com/shibboleth-idp/authn"
  }

  def "successful login of account with enforced totp but not having been setup yet renders account setup"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0, totpForce:true)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.redirectedUrl == "/login/setuptwostep"
    session.getAttribute(controller.CURRENT_USER) == ms.id
  }

  def "twosteplogin with invalid user denies request"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    when:
    controller.twosteplogin(123456)

    then:
    response.status == 403
    response.cookies.size() == 0
  }

  def "successful twosteplogin sets cookies and redirects to IdP login ssourl"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    controller.twosteplogin(123456)

    then:
    1 * loginService.twoStepLogin(ms, 123456, _, _) >> true
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"

    response.cookies.size() == 1
    response.cookies[0].maxAge == 60
    !response.cookies[0].secure
  }

  def "successful twosteplogin with uApprove session sets cookies and redirects to IdP login ssourl with uApprove param"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    session.setAttribute(controller.UAPPROVE_CONSENT_REVOKE, "true")
    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    controller.twosteplogin(123456)

    then:
    1 * loginService.twoStepLogin(ms, 123456, _, _) >> true
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn?uApprove.consent-revocation=true"

    response.cookies.size() == 1
    response.cookies[0].maxAge == 60
    !response.cookies[0].secure
  }

  def "setuptwostep with invalid user denies request"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    when:
    controller.setuptwostep()

    then:
    response.status == 403
    response.cookies.size() == 0
  }

  def "completesetuptwostep with invalid user denies request"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    when:
    controller.completesetuptwostep()

    then:
    response.status == 403
    response.cookies.size() == 0
  }

  def "completesetuptwostep with valid user renders QR code"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true
    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    def model = controller.completesetuptwostep()

    then:
    response.status == 200
    response.cookies.size() == 0
    model.totpURL
  }

  def "verifytwostepcode with invalid user denies request"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    session.setAttribute(controller.NEW_TOTP_KEY, "0")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    when:
    controller.verifytwostepcode(123456)

    then:
    response.status == 403
    response.cookies.size() == 0
  }

  def "verifytwostepcode with invalid code entry renders QR code"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    session.setAttribute(controller.NEW_TOTP_KEY, "0")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true
    session.setAttribute(controller.CURRENT_USER, ms.id)

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> false }

    when:
    controller.verifytwostepcode(123456)

    then:
    response.status == 200
    response.cookies.size() == 0
    model.totpURL
  }

  def "verifytwostepcode with valid code entry establishes session"() {
    setup:
    session.setAttribute(controller.SSO_URL, "https://idp.test.com/shibboleth-idp/authn")
    session.setAttribute(controller.NEW_TOTP_KEY, "0")

    def loginService = Mock(aaf.vhr.LoginService)
    grailsApplication.config.aaf.vhr.login.validity_period_minutes = 1
    grailsApplication.config.aaf.vhr.login.ssl_only_cookie = false

    controller.loginService = loginService

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true
    session.setAttribute(controller.CURRENT_USER, ms.id)

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> true }

    when:
    controller.verifytwostepcode(123456)

    then:
    1 * loginService.twoStepLogin(ms, 123456, _, _) >> true
    response.status == 302
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
    response.cookies.size() == 1
    response.cookies[0].maxAge == 60
    !response.cookies[0].secure
  }
}



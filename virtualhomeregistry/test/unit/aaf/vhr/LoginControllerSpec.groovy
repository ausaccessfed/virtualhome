package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import aaf.base.identity.*
import aaf.vhr.switchch.vho.DeprecatedSubject

@TestFor(aaf.vhr.LoginController)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject,aaf.vhr.switchch.vho.DeprecatedSubject])
@Mock([Organization, Group])
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

  def "current user sets loginError"() {
    setup:
    def ms = ManagedSubject.build()

    session.setAttribute(controller.SSO_URL, "http://test.com")
    session.setAttribute(controller.CURRENT_USER, ms.id)
  
    when:
    def model = controller.index()

    then:
    response.status == 200
    session.getAttribute(controller.CURRENT_USER) == null
    model.loginError
    !model.requiresChallenge
  }

  def "non migrated user goes directly to migrate controller"() {
    setup:
    def ds = DeprecatedSubject.build(login:'username', migrated:false)
  
    when:
    controller.login('username', 'passoword')

    then:
    response.status == 302
    response.redirectUrl == '/migrate/introduction'
    session.getAttribute(MigrateController.MIGRATION_USER) == 'username'
  }

  def "login withouth redirectURL redirects to oops"() {
    when:
    controller.login('username', 'password')

    then:
    response.redirectedUrl == "/login/oops"
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
    1 * loginService.webLogin(ms, _, _, _, _) >> [false, null]
    response.redirectedUrl == "/login/index"
    session.getAttribute(controller.CURRENT_USER) == ms.id
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
    1 * loginService.webLogin(ms, _, _, _, _) >> [true, 'abcd']
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
    response.cookies[0].maxAge == 1 * 60
    response.cookies[0].secure
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
    1 * loginService.webLogin(ms, _, _, _, _) >> [true, 'abcd']
    response.redirectedUrl == "https://idp.test.com/shibboleth-idp/authn"
    response.cookies[0].maxAge == 1 * 60
    !response.cookies[0].secure
  }

















}

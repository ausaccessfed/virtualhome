package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import aaf.vhr.crypto.GoogleAuthenticator

import spock.lang.*

import aaf.base.identity.*

@TestFor(aaf.vhr.AccountController)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject, aaf.base.identity.Subject, aaf.base.identity.Role, aaf.vhr.switchch.vho.DeprecatedSubject])
@Mock([Organization, Group])
class AccountControllerSpec extends spock.lang.Specification {
  def grailsApplication = new org.codehaus.groovy.grails.commons.DefaultGrailsApplication()

  def setup() {
  }

  def 'ensure index provides a view'() {
    when:
    controller.index()

    then:
    true
  }

  def "failed login renders to index"() {
    setup:
    def loginService = Mock(aaf.vhr.LoginService)

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> false
    view == '/account/index'
  }

  def "successful login redirect to show"() {
    setup:
    def loginService = Mock(aaf.vhr.LoginService)

    def ms = ManagedSubject.build(active:true, failedLogins: 0)
    ms.organization.active = true

    controller.loginService = loginService

    when:
    controller.login(ms.login, 'password')

    then:
    1 * loginService.passwordLogin(ms, _, _, _, _) >> true
    response.redirectedUrl == "/account/show"
  }

  def 'ensure logout invalidate session'() {
    setup:
    session.setAttribute('test', 'value')

    expect:
    session.getAttribute('test') == 'value'

    when:
    controller.logout()

    then:
    session.getAttribute('test') == null
    response.redirectedUrl == "/dashboard/welcome"
  }

  def 'show without session ManagedSubjectInstance directs to index'(){
    when:
    controller.show()

    then:
    response.redirectedUrl == "/account/index"
  }

  def 'show with exisiting session stored subject renders view'() {
    setup:
    def cryptoService = Mock(aaf.vhr.CryptoService)

    def managedSubjectTestInstance = ManagedSubject.build(login:'validlogin')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    controller.cryptoService = cryptoService

    when:
    def model = controller.show()

    then:
    0 * cryptoService.verifyPasswordHash(_ as String, _ as ManagedSubject) >>> true
    response.status == 200
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'changedetails with no existing login requires login'() {
    when:
    controller.changedetails()

    then:
    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.account.changedetails.requireslogin'
    response.redirectedUrl == '/account/index'
  }

  def 'changedetails with existing login succeeds'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login:'validlogin')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    when:
    def model = controller.changedetails()

    then:
    response.status == 200
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'completedetailschange with no existing login requires login'() {
    when:
    controller.completedetailschange()

    then:
    response.status == 403
  }

  def 'completedetailschange with existing login but wrong password fails'() {
    setup:
    def cryptoService = Mock(aaf.vhr.CryptoService)

    def managedSubjectTestInstance = ManagedSubject.build(login:'validlogin')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)
    params.currentPassword = 'password'

    controller.cryptoService = cryptoService

    when:
    controller.completedetailschange()

    then:
    1 * cryptoService.verifyPasswordHash(_ as String, _ as ManagedSubject) >>> false

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.account.completedetailschange.password.error'
    view == '/account/changedetails'
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'completedetailschange with existing login, correct current password but invalid new password fails'() {
    setup:
    def cryptoService = Mock(aaf.vhr.CryptoService)
    def passwordValidationService = Mock(aaf.vhr.PasswordValidationService)

    def managedSubjectTestInstance = ManagedSubject.build(login:'validlogin')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    params.currentPassword = 'password'
    params.plainPassword = 'newpassword'
    params.plainPasswordConfirmation = 'newpassword'

    controller.passwordValidationService = passwordValidationService
    controller.cryptoService = cryptoService

    when:
    controller.completedetailschange()

    then:
    1 * cryptoService.verifyPasswordHash(_ as String, _ as ManagedSubject) >>> true
    1 * passwordValidationService.validate(_ as ManagedSubject) >>> [[false, ['some.error', 'some.other.error']]]

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.account.completedetailschange.password.invalid'
    view == '/account/changedetails'
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'completedetailschange with existing login, correct current password and valid new password succeeds'() {
    setup:
    def cryptoService = Mock(aaf.vhr.CryptoService)
    def passwordValidationService = Mock(aaf.vhr.PasswordValidationService)

    def managedSubjectTestInstance = ManagedSubject.build(login:'validlogin')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    params.currentPassword = 'password'
    params.plainPassword = 'newpassword'
    params.plainPasswordConfirmation = 'newpassword'

    controller.cryptoService = cryptoService
    controller.passwordValidationService = passwordValidationService

    when:
    controller.completedetailschange()

    then:
    1 * cryptoService.verifyPasswordHash(_ as String, _ as ManagedSubject) >>> true
    1 * cryptoService.generatePasswordHash(_ as ManagedSubject)
    1 * passwordValidationService.validate(_ as ManagedSubject) >>> [[true, []]]

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.account.completedetailschange.success'
    response.redirectedUrl == '/account/show'
  }

  def 'completedetailschange updates mobile number when valid'() {
    setup:
    def cryptoService = Mock(aaf.vhr.CryptoService)
    controller.cryptoService = cryptoService

    def managedSubjectTestInstance = ManagedSubject.build(login: 'validlogin', mobileNumber: '+61487654321')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    when:
    params.currentPassword = 'password'
    params.mobileNumber = '+61412345678'
    controller.completedetailschange()

    then:
    1 * cryptoService.verifyPasswordHash(_, _) >> true

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.account.completedetailschange.success'

    managedSubjectTestInstance.mobileNumber == '+61412345678'
  }

  def 'ensure enabletwostep generates totpkey'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login: 'validlogin', mobileNumber: '+61487654321')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)

    when:
    controller.enabletwostep()

    then:
    response.status == 200
    session.getAttribute(controller.NEW_TOTP_KEY) != null
  }

  def 'ensure finishenablingtwostep fails with invalid code'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login: 'validlogin', mobileNumber: '+61487654321')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)
    session.setAttribute(controller.NEW_TOTP_KEY, "0")

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> false }

    expect:
    managedSubjectTestInstance.totpKey == null

    when:
    params.totp = 1
    controller.finishenablingtwostep()

    then:
    response.status == 200
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.account.finish.twostep.error'
  }

  def 'ensure finishenablingtwostep succeeds with valid code'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login: 'validlogin', mobileNumber: '+61487654321')
    session.setAttribute(controller.CURRENT_USER, managedSubjectTestInstance.id)
    session.setAttribute(controller.NEW_TOTP_KEY, "0")

    GoogleAuthenticator.metaClass.static.checkCode = { String key, long code, long time -> true }

    expect:
    managedSubjectTestInstance.totpKey == null

    when:
    params.totp = 1
    controller.finishenablingtwostep()

    then:
    response.status == 302
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.account.finish.twostep.success'
  }

}

package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import aaf.base.identity.*

@TestFor(aaf.vhr.LostPasswordController)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject, aaf.base.admin.EmailTemplate, aaf.base.identity.Subject, aaf.base.identity.Role, aaf.vhr.switchch.vho.DeprecatedSubject])
@Mock([Organization, Group, StateChange])
class LostPasswordControllerSpec extends spock.lang.Specification {

  def recaptchaService
  def passwordValidationService
  def cryptoService
  def emailManagerService

  def setup() {
    recaptchaService = Mock(com.megatome.grails.RecaptchaService)
    controller.recaptchaService = recaptchaService

    passwordValidationService = Mock(aaf.vhr.PasswordValidationService)
    controller.passwordValidationService = passwordValidationService

    cryptoService = Mock(aaf.vhr.CryptoService)
    controller.cryptoService = cryptoService

    emailManagerService = Mock(aaf.base.EmailManagerService)
    controller.emailManagerService = emailManagerService
  }

  def 'validManagedSubjectInstance errors if no managedsubject in session'() {
    when:
    def result = controller.validManagedSubjectInstance()

    then:
    !result
    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.lostpassword.requiresaccount'
    response.redirectedUrl == "/lostPassword/start"
  }

  def 'validManagedSubjectInstance errors if locked managedsubject in session'() {
    setup:
    grailsApplication.config.aaf.vhr.passwordreset.reset_attempt_limit = 5
    
    def ms = ManagedSubject.build(locked:true)
    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    def result = controller.validManagedSubjectInstance()

    then:
    !result
    response.redirectedUrl == "/lostPassword/locked"
  }

  def 'validManagedSubjectInstance errors if managedsubject in session has met failed attempts amount'() {
    setup:
    grailsApplication.config.aaf.vhr.passwordreset.reset_attempt_limit = 5

    def ms = ManagedSubject.build(locked:false, failedResets:5)
    ms.organization.active = true
    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    def result = controller.validManagedSubjectInstance()

    then:
    !result
    ms.stateChanges.size() == 1
    ms.stateChanges.toArray()[0].reason == "Locked by forgotten password process due to many failed login attempts"

    response.redirectedUrl == "/lostPassword/locked"
  }

  def 'validManagedSubjectInstance succeeds if valid managedsubject in session'() {
    setup:
    grailsApplication.config.aaf.vhr.passwordreset.reset_attempt_limit = 5

    def ms = ManagedSubject.build(locked:false, failedResets:2)
    ms.organization.active = true
    session.setAttribute(controller.CURRENT_USER, ms.id)

    when:
    def result = controller.validManagedSubjectInstance()

    then:
    result
  }

  def 'obtainsubject errors on invalid captcha'() {
    setup:
    params.login = 'testuser'

    when:
    controller.obtainsubject()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> false
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostpassword.recaptcha.error'
    view == '/lostPassword/start'
    model.login == 'testuser'
  }

  def 'obtainsubject errors if invalid login provided'() {
    setup:
    params.login = 'testuser'

    when:
    controller.obtainsubject()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.lostpassword.requiresaccount'
    response.redirectedUrl == "/lostPassword/start"
  }

  def 'obtainsubject errors if account can not change password'() {
    setup:
    def ms = ManagedSubject.build(login:'testuser', locked:true)
    params.login = 'testuser'

    when:
    controller.obtainsubject()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    response.redirectedUrl == "/lostPassword/locked"
  }

  def 'obtainsubject does not reset codes if not requested'() {
    setup:
    def o = Organization.build()
    def ms = ManagedSubject.build(login:'testuser', resetCode:'1234', resetCodeExternal:'5678')
    ms.organization.active = true
    params.login = 'testuser'

    when:
    controller.obtainsubject()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    response.redirectedUrl == "/lostPassword/reset"
    ms.resetCode == '1234'
    ms.resetCodeExternal == '5678'
  }

  def 'obtainsubject does reset codes if requested'() {
    setup:
    def ms = ManagedSubject.build(login:'testuser', resetCode:'1234', resetCodeExternal:'5678')
    ms.organization.active = true

    params.login = 'testuser'
    params.resetcodes = true

    when:
    controller.obtainsubject()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    response.redirectedUrl == "/lostPassword/reset"
    ms.resetCode == null
    ms.resetCodeExternal == null
  }

  def 'reset generates email code if not present'() {
    setup:
    def ms = ManagedSubject.build()
    session.setAttribute(controller.CURRENT_USER, ms.id)

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = false
    grailsApplication.config.aaf.vhr.passwordreset.reset_code_length = 6

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    expect:
    ms.resetCode == null

    when:
    def model = controller.reset()

    then:
    1 * emailManagerService.send(ms.email, _, _, [managedSubject:ms])
    ms.resetCode.length() == 6

    model.managedSubjectInstance == ms
    model.groupRole
    model.organizationRole
  }

  def 'reset does not sms if no mobileNumber'() {
    setup:
    def ms = ManagedSubject.build()
    session.setAttribute(controller.CURRENT_USER, ms.id)

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true
    grailsApplication.config.aaf.vhr.passwordreset.reset_code_length = 6

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    expect:
    ms.resetCode == null

    when:
    def model = controller.reset()

    then:
    1 * emailManagerService.send(ms.email, _, _, [managedSubject:ms])
    ms.resetCode.length() == 6
    ms.resetCodeExternal == null

    model.managedSubjectInstance == ms
    model.groupRole
    model.organizationRole
  }

  def 'reset does send sms if mobileNumber but redirects to unavailable on fault'() {
    setup:
    def ms = ManagedSubject.build(mobileNumber:'+61413234567')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true
    grailsApplication.config.aaf.vhr.passwordreset.reset_code_length = 6

    controller.metaClass.sendsms = {ManagedSubject ms2 -> ms2.resetCodeExternal = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(6); false}

    expect:
    ms.resetCode == null
    ms.resetCodeExternal == null

    when:
    def model = controller.reset()

    then:
    1 * emailManagerService.send(ms.email, _, _, [managedSubject:ms])
    ms.resetCode.length() == 6
    ms.resetCodeExternal.length() == 6

    response.redirectedUrl == "/lostPassword/unavailable"
  }

  def 'reset does send sms if mobileNumber'() {
    setup:
    def ms = ManagedSubject.build(mobileNumber:'+61413234567')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true
    grailsApplication.config.aaf.vhr.passwordreset.reset_code_length = 6

    controller.metaClass.sendsms = {ManagedSubject ms2 -> ms2.resetCodeExternal = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(6); true}

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    expect:
    ms.resetCode == null
    ms.resetCodeExternal == null

    when:
    def model = controller.reset()

    then:
    1 * emailManagerService.send(ms.email, _, _, [managedSubject:ms])
    ms.resetCode.length() == 6
    ms.resetCodeExternal.length() == 6

    model.managedSubjectInstance == ms
    model.groupRole
    model.organizationRole
  }

  def 'validatereset increases failure count it resetCodes do not match'() {
    setup:
    def ms = ManagedSubject.build(resetCode:'1234')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    params.resetCode = '5678'

    expect:
    ms.failedResets == 0

    when:
    controller.validatereset()

    then:
    ms.failedResets == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostpassword.emailcode.error'
    response.redirectedUrl == "/lostPassword/reset"
  }

  def 'validatereset increases failure count it resetCodeExternal does not match and second_factor_required'() {
    setup:
    def ms = ManagedSubject.build(resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    params.resetCode = '1234'
    params.resetCodeExternal = 'abcd'

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true

    expect:
    ms.failedResets == 0

    when:
    controller.validatereset()

    then:
    ms.failedResets == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostpassword.externalcode.error'
    response.redirectedUrl == "/lostPassword/reset"
  }

  def 'validatereset does not increase failure count if resetCodeExternal does not match with second_factor_required disabled'() {
    setup:
    def ms = ManagedSubject.build(resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    params.resetCode = '1234'
    params.resetCodeExternal = 'abcd'

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = false

    expect:
    ms.failedResets == 0

    when:
    controller.validatereset()

    then:
    ms.failedResets == 0
    1 * passwordValidationService.validate(_) >>> [[false, null]]
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostpassword.validatereset.new.password.invalid'
    view == '/lostPassword/reset'
    model.managedSubjectInstance == ms
    model.groupRole
    model.organizationRole
  }

  def 'validatereset does not increase counts but fails to pass on password format error'() {
    setup:
    def ms = ManagedSubject.build(resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    params.resetCode = '1234'
    params.resetCodeExternal = '5678'

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true

    expect:
    ms.failedResets == 0

    when:
    controller.validatereset()

    then:
    ms.failedResets == 0
    1 * passwordValidationService.validate(_) >>> [[false, null]]
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostpassword.validatereset.new.password.invalid'
    view == '/lostPassword/reset'
    model.managedSubjectInstance == ms
    model.groupRole
    model.organizationRole
  }

  def 'validatereset completes successfully with correct codes and valid password'() {
    setup:
    def ms = ManagedSubject.build(active:false, failedResets:1, failedLogins:2, resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    Role.build(name:"group:${ms.group.id}:administrators")
    Role.build(name:"organization:${ms.organization.id}:administrators")

    params.resetCode = '1234'
    params.resetCodeExternal = '5678'

    grailsApplication.config.aaf.vhr.passwordreset.second_factor_required = true

    expect:
    ms.failedResets == 1
    !ms.active

    when:
    controller.validatereset()

    then:
    1 * passwordValidationService.validate(_) >>> [[true, null]]
    1 * cryptoService.generatePasswordHash(ms)

    ms.active
    ms.failedLogins == 0
    ms.resetCode == null
    ms.resetCodeExternal == null
    ms.failedResets == 0

    session.getAttribute(controller.CURRENT_USER) == null

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.lostpassword.validatereset.new.password.success'
    response.redirectedUrl == "/lostPassword/complete"
  }

  def 'ensure locked reverts to start if no session object'() {
    when:
    controller.locked()

    then:
    response.redirectedUrl == "/lostPassword/start"
  }

  def 'ensure correct functioning of locked'() {
    setup:
    def ms = ManagedSubject.build(failedResets:1, resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    def gr = Role.build(name:"group:${ms.group.id}:administrators")
    def or = Role.build(name:"organization:${ms.organization.id}:administrators")

    when:
    def model = controller.locked()

    then:
    model.managedSubjectInstance == ms
    model.groupRole == gr
    model.organizationRole == or
  }

  def 'ensure logout invalidates session and redirects'() {
    setup:
    def ms = ManagedSubject.build(failedResets:1, resetCode:'1234', resetCodeExternal:'5678')
    session.setAttribute(controller.CURRENT_USER, ms.id)

    expect:
    session.getAttribute(controller.CURRENT_USER) == ms.id

    when:
    controller.logout()

    then:
    session.getAttribute(controller.CURRENT_USER) == null
    response.redirectedUrl == "/dashboard/welcome"
  }

}

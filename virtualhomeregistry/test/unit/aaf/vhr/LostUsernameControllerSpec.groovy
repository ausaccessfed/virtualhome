package aaf.vhr

import grails.test.mixin.TestFor
import spock.lang.*
import grails.buildtestdata.mixin.Build
import aaf.base.admin.EmailTemplate

@TestFor(LostUsernameController)
@Build([ManagedSubject, EmailTemplate])
@Mock([ManagedSubject, Group])
class LostUsernameControllerSpec extends Specification {
  def recaptchaService
  def emailManagerService

  def setup() {
    recaptchaService = Mock(com.megatome.grails.RecaptchaService)
    controller.recaptchaService = recaptchaService

    emailManagerService = Mock(aaf.base.EmailManagerService)
    controller.emailManagerService = emailManagerService
  }

  def 'start'() {
    when:
    controller.start()

    then:
    response.status == 200
  }

  def 'send errors on invalid captcha'() {
    setup:
    params.email = 'test@example.com'

    when:
    controller.send()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> false
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.lostusername.recaptcha.error'
    view == '/lostUsername/start'
    model.email == 'test@example.com'
  }

  def 'send succeeds for valid managed subject'() {
    setup:
    def ms = ManagedSubject.build(login: 'testuser', email: 'test@example.com')
    params.email = ms.email

    when:
    controller.send()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    1 * emailManagerService.send(_,_,_,[managedSubject:ms])
    response.redirectedUrl == '/lostUsername/complete'
  }

  def 'send succeeds when managed subject not found'() {
    setup:
    def ms = ManagedSubject.build(login: 'testuser', email: 'test@example.com')
    params.email = 'wrong-email@example.com'

    when:
    controller.send()

    then:
    1 * recaptchaService.verifyAnswer(_,_,_) >> true
    1 * emailManagerService.send(_,_,_,[managedSubject:null])
    response.redirectedUrl == '/lostUsername/complete'
  }
}

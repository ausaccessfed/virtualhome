package aaf.vhr

import org.springframework.context.i18n.LocaleContextHolder
import aaf.base.admin.EmailTemplate

class LostUsernameController {
  final String EMAIL_CODE_SUBJECT ='controllers.aaf.vhr.lostusername.email.subject'

  def recaptchaService
  def emailManagerService
  def messageSource

  def start() {}

  def send() {
    if (!recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
      log.error "Recaptcha incorrect when attempting to obtain subject"

      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.lostusername.recaptcha.error'
      render view:'start', model:[email: params.email]

      return
    }

    def managedSubjectInstance = ManagedSubject.findByEmail(params.email) // null is ok
    def emailSubject = messageSource.getMessage(EMAIL_CODE_SUBJECT, [] as Object[], EMAIL_CODE_SUBJECT, LocaleContextHolder.locale)
    def emailTemplate = EmailTemplate.findByName("email_lost_username")
    emailManagerService.send(params.email, emailSubject, emailTemplate, [managedSubject:managedSubjectInstance])

    redirect action: 'complete'
  }

  def complete() {
    //
  }
}

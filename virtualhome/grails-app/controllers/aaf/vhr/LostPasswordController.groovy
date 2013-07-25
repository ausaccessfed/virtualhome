package aaf.vhr

import groovyx.net.http.*
import static groovyx.net.http.ContentType.*
import static groovyx.net.http.Method.*
import org.springframework.context.i18n.LocaleContextHolder

import aaf.base.identity.Role
import aaf.base.admin.EmailTemplate
import aaf.vhr.switchch.vho.DeprecatedSubject

class LostPasswordController {

  final String CURRENT_USER = "aaf.vhr.LostPasswordController.CURRENT_USER"
  final String EMAIL_CODE_SUBJECT ='controllers.aaf.vhr.lostpassword.email.code.subject'

  final static defaultAction = "start"

  def messageSource
  def recaptchaService
  def passwordValidationService
  def cryptoService
  def emailManagerService

  def beforeInterceptor = [action: this.&validManagedSubjectInstance, except: ['start', 'obtainsubject', 'complete', 'unavailable', 'locked']]

  def start() {
  }

  def obtainsubject() {
    if (!recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
      log.error "Recaptcha incorrect when attempting to obtain subject"
        
      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.lostpassword.recaptcha.error'
      render view:'start', model:[login:params.login]

      return
    }

    def managedSubjectInstance = ManagedSubject.findWhere(login: params.login)
    if(!managedSubjectInstance) {
      log.error "No ManagedSubject representing ${params.login} found, requesting login before accessing password change"
      
      flash.type = 'info'
      flash.message = 'controllers.aaf.vhr.lostpassword.requiresaccount'
      redirect action: 'start'

      return
    }

    session.setAttribute(CURRENT_USER, managedSubjectInstance.id)

    if(!managedSubjectInstance.canChangePassword()) {
      log.error "Unable to reset password for $managedSubjectInstance as account is not currently able to change passwords"
      redirect action: 'locked'

      return
    }

    // Restart codes if user requests
    if(params.resetcodes) {
      managedSubjectInstance.resetCode = null
      managedSubjectInstance.resetCodeExternal = null

      if(!managedSubjectInstance.save()) {
        log.error "Unable to save $managedSubjectInstance when resetting password codes"
        managedSubjectInstance.errors.each {
          log.error it
        }
        redirect action: 'unavailable'
        return
      }
    }

    redirect action: 'reset'
  }

  def reset() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(managedSubjectInstance.resetCode == null || managedSubjectInstance.resetCodeExternal == null) {
      // Email reset code
      managedSubjectInstance.resetCode = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(grailsApplication.config.aaf.vhr.passwordreset.reset_code_length)
      def emailSubject = messageSource.getMessage(EMAIL_CODE_SUBJECT, [] as Object[], EMAIL_CODE_SUBJECT, LocaleContextHolder.locale)
      def emailTemplate = EmailTemplate.findWhere(name:"email_password_code")
      emailManagerService.send(managedSubjectInstance.email, emailSubject, emailTemplate, [managedSubject:managedSubjectInstance]) 

      if(grailsApplication.config.aaf.vhr.passwordreset.second_factor_required) {
        // SMS reset code (UI asks to contact admin if no mobile)
        if(managedSubjectInstance.mobileNumber) {
          if(!sendsms(managedSubjectInstance)) {
            redirect action: 'unavailable'
            return
          }
        }
      }
    }

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    [managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
  }

  def validatereset() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(managedSubjectInstance.resetCode != params.resetCode) {
      managedSubjectInstance.increaseFailedResets()

      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.lostpassword.emailcode.error'
      redirect action: 'reset'
      return
    }

    if(grailsApplication.config.aaf.vhr.passwordreset.second_factor_required) {
      if(managedSubjectInstance.resetCodeExternal != params.resetCodeExternal) {
        managedSubjectInstance.increaseFailedResets()

        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.lostpassword.externalcode.error'
        redirect action: 'reset'
        return
      }
    }

    managedSubjectInstance.plainPassword = params.plainPassword
    managedSubjectInstance.plainPasswordConfirmation = params.plainPasswordConfirmation

    def (validPassword, errors) = passwordValidationService.validate(managedSubjectInstance)
    if(!validPassword) {
      log.error "New password is invalid for $managedSubjectInstance"
      
      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.lostpassword.validatereset.new.password.invalid'

      def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
      def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

      render view: 'reset', model:[managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
      return
    }

    cryptoService.generatePasswordHash(managedSubjectInstance)
    managedSubjectInstance.successfulLostPassword()

    def deprecatedSubject = DeprecatedSubject.findWhere(login:managedSubjectInstance.login, migrated:false)
    if(deprecatedSubject) {
      deprecatedSubject.migrated = true 
      deprecatedSubject.save()
    }

    log.error "Successful LostPassword reset for $managedSubjectInstance"

    session.invalidate()

    flash.type = 'success'
    flash.message = 'controllers.aaf.vhr.lostpassword.validatereset.new.password.success'
    redirect action: 'complete'
  }

  def complete() { }

  def unavailable() { }

  def locked() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(!managedSubjectInstance) {
      log.error "Unable to present account locked details as managedSubjectInstance doesn't appear in session."
      redirect action: 'start'
      return
    }

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    [managedSubjectInstance:managedSubjectInstance, organizationRole:organizationRole, groupRole:groupRole]
  }

  def logout() {
    session.invalidate()
    redirect controller:'dashboard', action:'welcome'
  }

  private boolean validManagedSubjectInstance() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(!managedSubjectInstance) {
      log.error "No ManagedSubject stored in session, requesting login before accessing password change"
      
      flash.type = 'info'
      flash.message = 'controllers.aaf.vhr.lostpassword.requiresaccount'
      redirect action: 'start'
      return false
    }

    if(!managedSubjectInstance.canChangePassword() || managedSubjectInstance.failedResets >= grailsApplication.config.aaf.vhr.passwordreset.reset_attempt_limit.intValue()) {
      if(managedSubjectInstance.failedResets >= grailsApplication.config.aaf.vhr.passwordreset.reset_attempt_limit.intValue()) {
        String reason = "Locked by forgotten password process due to many failed login attempts"
        String requestDetails = """
User Agent: ${request.getHeader('User-Agent')}
Remote Host: ${request.getRemoteHost()}
Remote IP: ${request.getRemoteAddr()}"""

        managedSubjectInstance.lock(reason, 'lost_password_max_attempts_reached', requestDetails, null)
      }

      redirect action: 'locked'
      return false
    }

    true
  }

  private boolean sendsms(ManagedSubject managedSubjectInstance) {
    def passwordreset = grailsApplication.config.aaf.vhr.passwordreset

    managedSubjectInstance.resetCodeExternal = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(passwordreset.reset_code_length)

    String text = grailsApplication.config.aaf.vhr.passwordreset.reset_sms_text.replace('{0}', managedSubjectInstance.resetCodeExternal)
    String mobileNumber = managedSubjectInstance.mobileNumber

    boolean outcome = true
    def http = new HTTPBuilder( passwordreset.api_endpoint  )
    http.request( GET, JSON ) {
      uri.path = '/sms/json'
      uri.query = [api_key: passwordreset.api_key, api_secret:passwordreset.api_secret, from:'AAF', to:mobileNumber, type:'text', text:text]

      response.success = { resp, json ->
        log.debug resp.statusLine
        log.info "Sent SMS to $managedSubjectInstance with successful response of ${json.messages}"
        outcome = true

      }

      response.failure = { resp ->
        log.error "Sent SMS to $managedSubjectInstance with failure response of ${resp.statusLine.statusCode} : ${resp.statusLine.reasonPhrase}"
      }
    }
    
    outcome
  }

}

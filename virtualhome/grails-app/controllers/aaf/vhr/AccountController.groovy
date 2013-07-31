package aaf.vhr

import groovy.time.TimeCategory
import aaf.base.identity.SessionRecord

import aaf.base.identity.Role
import aaf.vhr.switchch.vho.DeprecatedSubject
import aaf.vhr.MigrateController

class AccountController {

  static allowedMethods = [completedetailschange: 'POST']

  final CURRENT_USER = "aaf.vhr.AccountController.CURRENT_USER"

  def loginService
  def cryptoService
  def passwordValidationService

  def index() { 
  }

  def login(String username, String password) {
    def deprecatedSubject = DeprecatedSubject.findWhere(login:username, migrated:false)
    if(deprecatedSubject) {
      session.setAttribute(MigrateController.MIGRATION_USER, username)
      redirect (controller:'migrate', action:'introduction')
      return
    }

    def managedSubjectInstance = ManagedSubject.findWhere(login: username, [lock:true])
    if(!managedSubjectInstance) {
      log.error "No such ManagedSubject for $params.login"
      
      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.account.login.error'
      render view: 'index', model:[loginError:true]

      return
    }

    def (loggedIn, sessionID) = loginService.webLogin(managedSubjectInstance, password, request, session, params)

    if(!loggedIn) {
      log.info "LoginService indicates failure for attempted login by $managedSubjectInstance to myaccount"
      session.setAttribute(CURRENT_USER, managedSubjectInstance.id)
      render view:'index', model:[loginError:true, requiresChallenge:managedSubjectInstance.requiresLoginCaptcha()]
      return
    }

    log.info "LoginService indicates success for login by ${managedSubjectInstance} to myaccount. Established sessionID of $sessionID"
    session.setAttribute(CURRENT_USER, managedSubjectInstance.id)

    redirect action:'show'
  }

  def logout() {
    session.invalidate()
    redirect controller:'dashboard', action:'welcome'
  }

  def show() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(!managedSubjectInstance) {
      redirect action:'index'
      return
    }

    flash.clear()

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    [managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
  }

  def changedetails() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))

    if(!managedSubjectInstance) {
      log.error "No ManagedSubject stored in session, requesting login before accessing details change"

      flash.type = 'info'
      flash.message = 'controllers.aaf.vhr.account.changedetails.requireslogin'
      redirect action: 'index'

      return
    }

    [managedSubjectInstance:managedSubjectInstance]
  }

  def completedetailschange() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow completedetailschange to function"

      response.sendError 403

      return
    }

    if(!cryptoService.verifyPasswordHash(params.currentPassword, managedSubjectInstance)) {
      log.error "Password invalid for $managedSubjectInstance"

      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.account.completedetailschange.password.error'
      render view: 'changedetails', model: [managedSubjectInstance:managedSubjectInstance]

      return
    }

    if (params.mobileNumber) {
      managedSubjectInstance.mobileNumber = params.mobileNumber
      if (!managedSubjectInstance.validate()) {
        log.error "New mobile number is invalid for $managedSubjectInstance"

        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.account.completedetailschange.mobileNumber.invalid'
        render view: 'changedetails', model: [managedSubjectInstance: managedSubjectInstance]
        return
      }
    } else {
      managedSubjectInstance.mobileNumber = null
    }

    if (params.plainPassword || params.plainPasswordConfirmation) {
      managedSubjectInstance.plainPassword = params.plainPassword
      managedSubjectInstance.plainPasswordConfirmation = params.plainPasswordConfirmation

      def (validPassword, errors) = passwordValidationService.validate(managedSubjectInstance)
      if(!validPassword) {
        log.error "New password is invalid for $managedSubjectInstance"

        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.account.completedetailschange.password.invalid'
        render view: 'changedetails', model: [managedSubjectInstance:managedSubjectInstance]

        return
      }

      cryptoService.generatePasswordHash(managedSubjectInstance)
    }

    flash.type = 'success'
    flash.message = 'controllers.aaf.vhr.account.completedetailschange.success'
    redirect action: 'show'
  }

  private String createRequestDetails(def request) {
"""User Agent: ${request.getHeader('User-Agent')}
Remote Host: ${request.getRemoteHost()}
Remote IP: ${request.getRemoteAddr()}"""
  }
}

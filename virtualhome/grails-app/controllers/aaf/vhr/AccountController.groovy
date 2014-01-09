package aaf.vhr

import groovy.time.TimeCategory
import aaf.base.identity.SessionRecord

import aaf.base.identity.Role
import aaf.vhr.switchch.vho.DeprecatedSubject

import aaf.vhr.crypto.GoogleAuthenticator

class AccountController {

  static allowedMethods = [completedetailschange: 'POST']

  static final CURRENT_USER = "aaf.vhr.AccountController.CURRENT_USER"

  def loginService
  def cryptoService
  def passwordValidationService
  def grailsApplication

  def index() {
  }

  def login(String username, String password) {
    def managedSubjectInstance = ManagedSubject.findWhere(login: username, [lock:true])
    if(!managedSubjectInstance) {
      log.error "No such ManagedSubject for ${params.login} when attempting myaccount login"

      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.account.login.error'
      render view: 'index', model:[loginError:true]

      return
    }

    def validPassword = loginService.passwordLogin(managedSubjectInstance, password, request, session, params)

    if(!validPassword) {
      log.info "LoginService indicates failure for password login by $managedSubjectInstance to myaccount"
      session.setAttribute(CURRENT_USER, managedSubjectInstance.id)
      render view:'index', model:[loginError:true, requiresChallenge:managedSubjectInstance.requiresLoginCaptcha()]
      return
    }

    if(managedSubjectInstance.isUsingTwoStepLogin()){
      render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance])
      return
    }

    session.setAttribute(CURRENT_USER, managedSubjectInstance.id)
    redirect action:'show'
  }

  def twosteplogin(long id, long totp) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(!managedSubjectInstance) {
      log.error "No ManagedSubject represented by $id in extendedlogin"
      session.setAttribute(INVALID_USER, true)
      redirect action:"index"
      return
    }

    if(!loginService.twoStepLogin(managedSubjectInstance, totp, request, response)) {
      log.info "LoginService indicates 2-Step verification failure for attempted login by $managedSubjectInstance"
      render(view: "twostep", model: [managedSubjectInstance: managedSubjectInstance, loginError:true])
      return
    }

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

    def totpURL = null
    if(managedSubjectInstance.isUsingTwoStepLogin())
      totpURL = GoogleAuthenticator.getQRBarcodeURL(managedSubjectInstance.login, "VHO", managedSubjectInstance.totpKey)

    [managedSubjectInstance:managedSubjectInstance, totpURL: totpURL, groupRole:groupRole, organizationRole:organizationRole]
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

  def enabletwostep() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow completedetailschange to function"
      response.sendError 403
      return
    }

    managedSubjectInstance.totpKey = GoogleAuthenticator.generateSecretKey()
    if(!managedSubjectInstance.save()) {
      log.error "Unable to persist totpKey for $managedSubjectInstance"
      response.sendError 500
      return
    }

    redirect action:'show'
  }

  def setuptwostep() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow completedetailschange to function"
      response.sendError 403
      return
    }

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    [managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
  }

  def completesetuptwostep() {
    def managedSubjectInstance = ManagedSubject.get(session.getAttribute(CURRENT_USER))
    if(!managedSubjectInstance) {
      log.error "A valid session does not already exist to allow completedetailschange to function"
      response.sendError 403
      return
    }

    managedSubjectInstance.totpKey = GoogleAuthenticator.generateSecretKey()
    if(!managedSubjectInstance.save()) {
      log.error "Unable to persist totpKey for $managedSubjectInstance"
      response.sendError 500
      return
    }

    def totpURL = GoogleAuthenticator.getQRBarcodeURL(managedSubjectInstance.login, "VHO", managedSubjectInstance.totpKey)

    [managedSubjectInstance:managedSubjectInstance, totpURL:totpURL]
  }

  private String createRequestDetails(def request) {
"""User Agent: ${request.getHeader('User-Agent')}
Remote Host: ${request.getRemoteHost()}
Remote IP: ${request.getRemoteAddr()}"""
  }
}

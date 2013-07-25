package aaf.vhr

import aaf.vhr.switchch.vho.DeprecatedSubject
import aaf.base.identity.Role

import java.security.MessageDigest

class MigrateController {

  public static final MIGRATION_USER = "aaf.vhr.MigrateController.USER"

  def beforeInterceptor = [action: this.&validMigrationUser, except: ['oops']]

  def grailsApplication
  def recaptchaService
  def passwordValidationService
  def cryptoService
  
  def introduction() {
  }

  def providedetails() {
    def managedSubjectInstance = ManagedSubject.findWhere(login:session.getAttribute(MigrateController.MIGRATION_USER))
    [managedSubjectInstance:managedSubjectInstance, requiresChallenge:false]
  }

  def validate() {
    def managedSubjectInstance = ManagedSubject.findWhere(login:session.getAttribute(MigrateController.MIGRATION_USER))
    def deprecatedSubject = DeprecatedSubject.findWhere(login:session.getAttribute(MigrateController.MIGRATION_USER))

    log.info "Attempting account migration and validation for $managedSubjectInstance"

    // We're more generous with attempts to assist migration
    def requireCaptchaAttempts = grailsApplication.config.aaf.vhr.login.require_captcha_after_tries * 3

    if(deprecatedSubject.migrationAttempts >= requireCaptchaAttempts && 
      !recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
      log.error "Provided captcha invalid for $managedSubjectInstance"

      deprecatedSubject.migrationAttempts++
      if(!deprecatedSubject.save()) {
        deprecatedSubject.errors.each { log.error it }
        response.sendError 500
        return
      }

      flash.type = 'error'
      flash.message = 'Unfortunately you entered the wrong information for your challenge question. Please try again.'
      render view: 'providedetails', model: [managedSubjectInstance:managedSubjectInstance, requiresChallenge:deprecatedSubject.migrationAttempts >= requireCaptchaAttempts]
      return
    }

    if(params.currentPassword.encodeAsMD5() != deprecatedSubject.password) {
      log.error "Previous password invalid for $managedSubjectInstance"

      deprecatedSubject.migrationAttempts++
      if(!deprecatedSubject.save()) {
        deprecatedSubject.errors.each { log.error it }
        response.sendError 500
        return
      }
      
      flash.type = 'error'
      flash.message = 'The value you provided as your current password is incorrect. Please try again.'
      render view: 'providedetails', model: [managedSubjectInstance:managedSubjectInstance, requiresChallenge:deprecatedSubject.migrationAttempts >= requireCaptchaAttempts]

      return
    }

    managedSubjectInstance.plainPassword = params.plainPassword
    managedSubjectInstance.plainPasswordConfirmation = params.plainPasswordConfirmation

    if(params.mobileNumber)
      managedSubjectInstance.mobileNumber = params.mobileNumber
    else
      managedSubjectInstance.mobileNumber = null

    managedSubjectInstance.validate()
    def (validPassword, errors) = passwordValidationService.validate(managedSubjectInstance)
    if(!validPassword) {
      log.error "New password is invalid for $managedSubjectInstance"

      deprecatedSubject.migrationAttempts++
      if(!deprecatedSubject.save()) {
        deprecatedSubject.errors.each { log.error it }
        response.sendError 500
        return
      }
      
      flash.type = 'error'
      flash.message = 'Unfortunately the new password you selected does not meet our minimum requirements. Please try again.'
      render view: 'providedetails', model: [managedSubjectInstance:managedSubjectInstance, requiresChallenge:deprecatedSubject.migrationAttempts >= requireCaptchaAttempts]

      return
    }

    if(managedSubjectInstance.hasErrors()) {
      log.error "New mobile number ${managedSubjectInstance.mobileNumber} is invalid for $managedSubjectInstance"
      
      flash.type = 'error'
      flash.message = 'Unfortunately the mobile number you provided is not valid. Please try again.'
      render view: 'providedetails', model: [managedSubjectInstance:managedSubjectInstance, requiresChallenge:deprecatedSubject.migrationAttempts >= requireCaptchaAttempts]

      return
    }

    cryptoService.generatePasswordHash(managedSubjectInstance)

    if(!managedSubjectInstance.save()) {
      managedSubjectInstance.errors.each { log.error it }
      response.sendError 500
      return
    }

    deprecatedSubject.migrated = true
    if(!deprecatedSubject.save()) {
      deprecatedSubject.errors.each { log.error it }
      response.sendError 500
      return
    }

    if(managedSubjectInstance.canLogin()) {
      log.info "Migrated and validated $managedSubjectInstance. They can now login using VHR"
      redirect action:'complete'
    } else {
      log.info "Migrated and validated $managedSubjectInstance. They can not login however as the account is not functioning."
      redirect action:'expired'
    }
  }

  def expired() {
    def managedSubjectInstance = ManagedSubject.findWhere(login:session.getAttribute(MigrateController.MIGRATION_USER))

    def groupRole = Role.findWhere(name:"group:${managedSubjectInstance.group.id}:administrators")
    def organizationRole = Role.findWhere(name:"organization:${managedSubjectInstance.organization.id}:administrators")

    session.removeAttribute(MigrateController.MIGRATION_USER)

    [managedSubjectInstance:managedSubjectInstance, groupRole:groupRole, organizationRole:organizationRole]
  }

  def complete() {
    session.removeAttribute(MigrateController.MIGRATION_USER)
  }

  def oops() {

  }

  def logout() {
    session.invalidate()
    redirect controller:'dashboard', action:'welcome'
  }

  boolean validMigrationUser() {
    if(!session.getAttribute(MigrateController.MIGRATION_USER)) {
      redirect action: 'oops'
      return false
    }
    return true
  }
}

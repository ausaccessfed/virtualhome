package aaf.vhr

import groovy.time.TimeCategory
import aaf.base.identity.SessionRecord

class FinalizationController {
  static final MANAGED_SUBJECT_ID = 'aaf.vhr.FinalizationController.MANAGED_SUBJECT_ID'

  def managedSubjectService
  
  def index(String inviteCode) {
    def invitationInstance = ManagedSubjectInvitation.findWhere(inviteCode:inviteCode)
    session.setAttribute(MANAGED_SUBJECT_ID, invitationInstance?.managedSubject?.id)

    if(!invitationInstance) {
      log.error "no such invitation exists"
      redirect action: 'error'
      return
    }

    if(invitationInstance.utilized) {
      redirect action: 'used'
      return
    }

    [managedSubjectInstance:invitationInstance.managedSubject, invitationInstance:invitationInstance]
  }

  def loginAvailable(String login) {
    if(login.contains(' ')) {
      render "false"
      return
    }

    def managedSubjectInstance = ManagedSubject.findWhere(login:login)
    if(managedSubjectInstance && managedSubjectInstance.id != session.getAttribute(MANAGED_SUBJECT_ID))
      render "false"
    else
      render "true"
  }

  def complete(String inviteCode, String login, String plainPassword, String plainPasswordConfirmation, String mobileNumber) {
    def invitationInstance = ManagedSubjectInvitation.findWhere(inviteCode:inviteCode)

    if(!invitationInstance) {
      log.error "no such invitation exists"
      redirect action: 'error'
      return
    }

    def (outcome, managedSubjectInstance) = managedSubjectService.finalize(invitationInstance, login, plainPassword, plainPasswordConfirmation, mobileNumber ?:null)
    if(!outcome) {
      render (view: 'index', model:[managedSubjectInstance:managedSubjectInstance, invitationInstance:invitationInstance])
      return
    }
    [managedSubjectInstance: managedSubjectInstance]
  }

  def used() {
  }

  def error() {
  }
}

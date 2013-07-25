package aaf.vhr

import org.springframework.dao.DataIntegrityViolationException
import org.apache.shiro.SecurityUtils

class ManagedSubjectController {

  static defaultAction = "list"
  static allowedMethods = [save: "POST", update: "POST", delete: "DELETE", resend:"POST"]

  def beforeInterceptor = [action: this.&validManagedSubject, except: ['list', 'create', 'save', 'createcsv', 'savecsv']]

  def grailsApplication
  def managedSubjectService
  def sharedTokenService

  def list() {
    if(SecurityUtils.subject.isPermitted("app:administrator")) {
      log.info "Action: list, Subject: $subject"
      [managedSubjectInstanceList: ManagedSubject.list(params), managedSubjectInstanceTotal: ManagedSubject.count()]
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject list by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def show(Long id) {
    def managedSubjectInstance = ManagedSubject.get(id)

    if(managedSubjectInstance.canShow()) {
      log.info "Action: show, Subject: $subject, Object: $managedSubjectInstance"
      [managedSubjectInstance: managedSubjectInstance]
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject show by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def create() {
    if(validGroup()) {
      def group = Group.get(params.group.id)
      def managedSubjectInstance = new ManagedSubject(group:group, organization:group.organization)

      if(managedSubjectInstance.canCreate(group)) {
        log.info "Action: create, Subject: $subject"
        [managedSubjectInstance: managedSubjectInstance]
      }
      else {
        log.warn "Attempt to do administrative ManagedSubject create by $subject was denied - not permitted by assigned permissions"
        response.sendError 403
      }
    }
  }

  def save() {
    if(validGroup()) {
      def group = Group.get(params.group.id)
      def managedSubjectInstance = new ManagedSubject(group:group, organization:group.organization)

      if(managedSubjectInstance.canCreate(group)) {
        bindData(managedSubjectInstance, params, [include: ['cn', 'email', 'eduPersonAssurance', 'eduPersonEntitlement', 'accountExpires']])
        managedSubjectInstance.displayName = managedSubjectInstance.cn
        sharedTokenService.generate(managedSubjectInstance)

        if(params.eduPersonAffiliation instanceof String)
          managedSubjectInstance.eduPersonAffiliation = params.eduPersonAffiliation
        else
          managedSubjectInstance.eduPersonAffiliation = params.eduPersonAffiliation.join(';')

        if(params.eduPersonEntitlement) {
          managedSubjectInstance.eduPersonEntitlement = params.eduPersonEntitlement.replaceAll("\r\n|\n\r|\n|\r",";")
        }

        if(SecurityUtils.subject.isPermitted("app:administrator") && params.sharedToken) {
          managedSubjectInstance.sharedToken = params.sharedToken
        }

        if(!group.organization.canRegisterSubjects() && !SecurityUtils.subject.isPermitted("app:administrator")) {
          flash.type = 'error'
          flash.message = 'controllers.aaf.vhr.managedsubject.licensing.failed'
          render(view: "create", model: [managedSubjectInstance: managedSubjectInstance])
          return
        }

        if (!managedSubjectInstance.validate()) {
          managedSubjectInstance.errors.each { println it}
          flash.type = 'error'
          flash.message = 'controllers.aaf.vhr.managedsubject.validate.failed'
          render(view: "create", model: [managedSubjectInstance: managedSubjectInstance])
          return
        }

        managedSubjectService.register(managedSubjectInstance)

        log.info "Action: save, Subject: $subject, Object: $managedSubjectInstance"
        flash.type = 'success'
        flash.message = 'controllers.aaf.vhr.managedsubject.save.success'
        redirect(action: "show", id: managedSubjectInstance.id)
      }
      else {
        log.warn "Attempt to do administrative ManagedSubject save by $subject was denied - not permitted by assigned permissions"
        response.sendError 403
      }
    }
  }

  def createcsv() {
    if(validGroup()) {
      def group = Group.get(params.group.id)
      def managedSubjectInstance = new ManagedSubject(group:group, organization:group.organization)

      if(managedSubjectInstance.canCreate(group)) {
        log.info "Action: create, Subject: $subject"
        [groupInstance: group]
      }
      else {
        log.warn "Attempt to do administrative ManagedSubject create by $subject was denied - not permitted by assigned permissions"
        response.sendError 403
      }
    }
  }

  def savecsv() {
    if(validGroup()) {
      def group = Group.get(params.group.id)
      def managedSubjectInstance = new ManagedSubject(group:group, organization:group.organization)

      if(managedSubjectInstance.canCreate(group)) {
        def csv = request.getFile('csvdata')
        if (csv.empty) {
          flash.type = 'error'
          flash.message = 'controllers.aaf.vhr.managedsubject.savecsv.nodata'
          render(view: 'createcsv')
          return
        }

        def (status, errors, subjects, linecount) = managedSubjectService.registerFromCSV(group, csv.getBytes())

        if(!status) {
          flash.type = 'error'
          flash.message = 'controllers.aaf.vhr.managedsubject.savecsv.registererror'
          render(view: 'createcsv', model:[groupInstance: group, status: status, errors:errors, managedSubjectInstances:subjects, linecount:linecount])
          return
        }

        [groupInstance:group, status: status, errors:errors, managedSubjectInstances:subjects, linecount:linecount]
      }
      else {
        log.warn "Attempt to do administrative ManagedSubject csv upload by $subject was denied - not permitted by assigned permissions"
        response.sendError 403
      }
    }
  }

  def edit(Long id) {
    def managedSubjectInstance = ManagedSubject.get(id)

    if(!SecurityUtils.subject.isPermitted('app:administrator') && managedSubjectInstance.login == null) {
      log.warn "Attempt to do administrative ManagedSubject edit by $subject was denied - not global administrator, and account has not been finalized"
      flash.type = 'error'
      flash.message = 'controllers.aaf.vhr.managedsubject.edit.notfinalized'
      redirect(action: "show", id: managedSubjectInstance.id)
      return
    }

    if(managedSubjectInstance.canMutate()) {
      log.info "Action: edit, Subject: $subject, Object: managedSubjectInstance"

      [managedSubjectInstance: managedSubjectInstance]
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject edit by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def update(Long id, Long version) {
    def managedSubjectInstance = ManagedSubject.get(id)

    if(!SecurityUtils.subject.isPermitted('app:administrator') && managedSubjectInstance.login == null) {
      log.warn "Attempt to do administrative ManagedSubject edit by $subject was denied - not global administrator, and account has not been finalized"
      response.sendError 403
      return
    }

    if(managedSubjectInstance.canMutate()) {
      if (version == null) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.update.noversion'
        render(view: "edit", model: [managedSubjectInstance: managedSubjectInstance])
        return
      }

      if (managedSubjectInstance.version > version) {
        managedSubjectInstance.errors.rejectValue("version", "controllers.aaf.vhr.managedsubject.update.optimistic.locking.failure")
        render(view: "edit", model: [managedSubjectInstance: managedSubjectInstance])
        return
      }

      bindData(managedSubjectInstance, params, [include: ['login', 'cn', 'email', 'eduPersonAssurance', 'displayName', 'accountExpires', 
                                                          'givenName', 'surname', 'mobileNumber', 'telephoneNumber', 'postalAddress', 
                                                          'organizationalUnit']])

      if(SecurityUtils.subject.isPermitted("app:administrator")) {
        bindData(managedSubjectInstance, params, [include: 'sharedToken'])
      }

      if(params.eduPersonAffiliation instanceof String)
        managedSubjectInstance.eduPersonAffiliation = params.eduPersonAffiliation
      else
        managedSubjectInstance.eduPersonAffiliation = params.eduPersonAffiliation.join(';')

      if(params.eduPersonEntitlement) {
        managedSubjectInstance.eduPersonEntitlement = params.eduPersonEntitlement.replaceAll("\r\n|\n\r|\n|\r",";")
      }

      if (!managedSubjectInstance.save()) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.update.failed'
        render(view: "edit", model: [managedSubjectInstance: managedSubjectInstance])
        return
      }

      log.info "Action: update, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.update.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject update by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def delete(Long id) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canDelete()) {
      try {
        managedSubjectInstance.delete()

        log.info "Action: delete, Subject: $subject, Object: $managedSubjectInstance"
        flash.type = 'success'
        flash.message = 'controllers.aaf.vhr.managedsubject.delete.success'
        redirect(controller:"group", action: "show", id: managedSubjectInstance.group.id, fragment:"tab-accounts")
      }
      catch (DataIntegrityViolationException e) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.delete.failure'
        redirect(action: "show", id: id)
      }
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject delete by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def resend(Long id) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canMutate()) {
      managedSubjectService.sendConfirmation(managedSubjectInstance)

      log.info "Action: resend, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.resend.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject resend by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def admincode(Long id) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canMutate()) {
      managedSubjectInstance.resetCodeExternal = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(grailsApplication.config.aaf.vhr.passwordreset.reset_code_length)

      if (!managedSubjectInstance.save()) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.admincode.failed'
        redirect(action: "show", id: managedSubjectInstance.id)
        return
      }

      [managedSubjectInstance: managedSubjectInstance]

    } else {
      log.warn "Attempt to do administrative ManagedSubject lost password code generation by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def toggleBlock(Long id, Long version) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(SecurityUtils.subject.isPermitted("app:administration")) {
      if (version == null) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.toggleblock.noversion'
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if (managedSubjectInstance.version > version) {
        managedSubjectInstance.errors.rejectValue("version", "controllers.aaf.vhr.managedsubject.toggleblock.optimistic.locking.failure")
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if(managedSubjectInstance.blocked) {
        managedSubjectInstance.unblock("Unblocked by super administrator", "vhr_management_portal", null, subject)
      } else {
        managedSubjectInstance.block("Blocked by administrator", "vhr_management_portal", null, subject)
      }

      log.info "Action: toggleBlock, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.toggleblock.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject togglelock by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def toggleLock(Long id, Long version) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canMutate()) {
      if (version == null) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.togglelock.noversion'
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if (managedSubjectInstance.version > version) {
        managedSubjectInstance.errors.rejectValue("version", "controllers.aaf.vhr.managedsubject.togglelock.optimistic.locking.failure")
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if(managedSubjectInstance.locked) {
        managedSubjectInstance.unlock("Unlocked by administrator", "vhr_management_portal", null, subject)
      } else {
        managedSubjectInstance.lock("Locked by administrator", "vhr_management_portal", null, subject)
      }

      log.info "Action: toggleLock, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.togglelock.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject togglelock by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def toggleActive(Long id, Long version) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canMutate()) {
      if (version == null) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.toggleactive.noversion'
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if (managedSubjectInstance.version > version) {
        managedSubjectInstance.errors.rejectValue("version", "controllers.aaf.vhr.managedsubject.toggleactive.optimistic.locking.failure")
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if(managedSubjectInstance.active) {
        managedSubjectInstance.deactivate("Deactivated by administrator", "vhr_management_portal", null, subject)
      } else {
        managedSubjectInstance.activate("Activated by administrator", "vhr_management_portal", null, subject)
      }

      log.info "Action: toggleActive, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.toggleactive.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject toggleactive by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  def toggleArchive(Long id, Long version) {
    def managedSubjectInstance = ManagedSubject.get(id)
    if(managedSubjectInstance.canMutate()) {
      if (version == null) {
        flash.type = 'error'
        flash.message = 'controllers.aaf.vhr.managedsubject.togglearchive.noversion'
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if (managedSubjectInstance.version > version) {
        managedSubjectInstance.errors.rejectValue("version", "controllers.aaf.vhr.managedsubject.togglearchive.optimistic.locking.failure")
        render(view: "show", model:[managedSubjectInstance: managedSubjectInstance])
        return
      }

      if(managedSubjectInstance.archived) {
        managedSubjectInstance.unarchive("Unarchived by administrator", "vhr_management_portal", null, subject)
      } else {
        managedSubjectInstance.archive("Archived by administrator", "vhr_management_portal", null, subject)
      }

      log.info "Action: toggleActive, Subject: $subject, Object: $managedSubjectInstance"
      flash.type = 'success'
      flash.message = 'controllers.aaf.vhr.managedsubject.togglearchive.success'
      redirect(action: "show", id: managedSubjectInstance.id)
    }
    else {
      log.warn "Attempt to do administrative ManagedSubject togglearchive by $subject was denied - not permitted by assigned permissions"
      response.sendError 403
    }
  }

  private validGroup() {
    if(!params.group?.id) {
      log.warn "Group ID was not present"

      response.sendError 404
      return false
    }

    def groupInstance = Group.get(params.group.id)
    if (!groupInstance) {
      log.warn "groupInstance was not a valid instance"

      response.sendError 404
      return false
    }

    true
  }

  private validManagedSubject() {
    if(!params.id) {
      log.warn "ID was not present"

      response.sendError 404
      return false
    }

    def managedSubjectInstance = ManagedSubject.get(params.id)
    if (!managedSubjectInstance) {
      log.warn "managedSubjectInstance was not a valid instance"

      response.sendError 404
      return false
    }
  }
}

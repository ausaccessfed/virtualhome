import aaf.vhr.*

import aaf.base.identity.*
import aaf.base.admin.*
import aaf.base.workflow.*

import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.apache.shiro.SecurityUtils

import grails.util.Environment

class BootStrap {

  def grailsApplication
  def workflowProcessService

    def init = { servletContext ->
      // TODO: Remove this next major release
      if (!grailsApplication.config.aaf.base.sms.api_endpoint) {
        // Backward compatibility of configuration
        grailsApplication.config.aaf.base.sms = grailsApplication.config.aaf.vhr.passwordreset
      }

      if(Environment.current != Environment.TEST) {

        def subject = aaf.base.identity.Subject.findWhere(principal:"aaf.base.identity:internal_account")
        if(!subject) {
          throw new RuntimeException("Unable to retrieve initial subject reference \
            'aaf.base.identity:internal_account' which should be populated by base")
        }

        def organization_approval = WorkflowScript.findWhere(name:'organization_approval')
        if(!organization_approval) {
          def scriptMarkup = grailsApplication.parentContext.getResource("classpath:aaf/vhr/organization_approval.scr").inputStream.text
          organization_approval = new WorkflowScript(name:'organization_approval', description:'Executed to finalize new Organization', definition:scriptMarkup, , processVersion:1, creator:subject)
          if(!organization_approval.save()) {
            organization_approval.errors.each {
              println it
            }
            throw new RuntimeException("Unable to populate initial workflow script organization_approval")
          }
        }

        def organization_creation_process = Process.findWhere(name:'organization_creation_process')
        if(!organization_creation_process) {

          def suMetaClass = new ExpandoMetaClass(SecurityUtils)
          suMetaClass.'static'.getSubject = {[getPrincipal:{subject.id}] as Subject}
          suMetaClass.initialize()
          SecurityUtils.metaClass = suMetaClass

          def processMarkup = grailsApplication.parentContext.getResource("classpath:aaf/vhr/organization_creation_workflow.pr").inputStream.text
          workflowProcessService.create(processMarkup)

          SecurityUtils.metaClass = null
        }

        def seedEmailTemplate = { name ->
          def template = EmailTemplate.findWhere(name: name)
          if(!template) {
            def templateMarkup = grailsApplication.parentContext.getResource("classpath:aaf/vhr/${name}.gsp").inputStream.text
            template = new EmailTemplate(name: name, content: templateMarkup)
            if(!template.save()) {
              template.errors.each {
                println it
              }
              throw new RuntimeException("Unable to populate initial email template $name")
            }
          }
        }

        seedEmailTemplate('registered_managed_subject')
        seedEmailTemplate('approved_new_organization')
        seedEmailTemplate('email_password_code')
        seedEmailTemplate('email_lost_username')
      }
    }

    def destroy = {
    }
}

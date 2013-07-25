package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

@TestFor(aaf.vhr.OrganizationController)
@Build([Organization, Group, aaf.base.identity.Subject, aaf.base.identity.Role])
class OrganizationControllerSpec  extends spock.lang.Specification {
  
  @Shared def shiroEnvironment = new ShiroEnvironment()

  aaf.base.identity.Subject subject
  org.apache.shiro.subject.Subject shiroSubject
  
  def cleanupSpec() { 
    shiroEnvironment.tearDownShiro() 
  }

  def setup() {
    subject = aaf.base.identity.Subject.build()

    shiroSubject = Mock(org.apache.shiro.subject.Subject)
    shiroSubject.id >> subject.id
    shiroSubject.principal >> subject.principal
    shiroSubject.isAuthenticated() >> true
    shiroEnvironment.setSubject(shiroSubject)
    
    controller.metaClass.getSubject = { subject }
  }

  def 'ensure beforeInterceptor only excludes list, create, save'() {
    when:
    controller

    then:
    controller.beforeInterceptor.except.size() == 3
    controller.beforeInterceptor.except.containsAll(['list', 'create', 'save'])
  }

  def 'ensure redirect to list if no ID presented to beforeInterceptor'() {
    when:
    def result = controller.validOrganization()

    then:
    !result
    response.status == 302

    response.redirectedUrl == "/organization/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.organization.no.id'
  }

  def 'ensure redirect to list if no valid instance found by beforeInterceptor'() {
    when:
    params.id = 1
    def result = controller.validOrganization()

    then:
    !result
    response.status == 302

    response.redirectedUrl== "/organization/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.organization.notfound'
  }

  def 'ensure correct output from list'() {
    setup:
    (1..10).each { Organization.build() }

    when:
    params.max = max
    def model = controller.list()

    then:
    Organization.count() == total
    model.organizationInstanceList.size() == expectedResult

    where:
    max | total | expectedResult
    0 | 10 | 10
    5 | 10 | 5
  }

  def 'ensure correct output from show'() {
    setup:
    def organizationTestInstance = Organization.build()

    when:
    params.id = organizationTestInstance.id
    def model = controller.show()

    then:
    model.organizationInstance == organizationTestInstance
  }

  def 'ensure correct output from create when valid permission'() {
    setup:
    shiroSubject.isPermitted("app:administrator") >> true

    when:
    def model = controller.create()

    then:
    model.organizationInstance.instanceOf(Organization)
  }

  def 'ensure correct output from create when invalid permission'() {
    setup:
    shiroSubject.isPermitted("app:manage:organization:create") >> false

    when:
    def model = controller.create()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save when invalid permission'() {
    setup:
    shiroSubject.isPermitted("app:manage:organization:create") >> false

    when:
    def model = controller.save()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save with invalid data and when valid permission'() {
    setup:
    def organizationService = Mock(aaf.vhr.OrganizationService)

    shiroSubject.isPermitted("app:administrator") >> true

    def organizationTestInstance = Organization.build()
    organizationTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    organizationTestInstance.delete()

    Organization.metaClass.save { null }

    organizationService.metaClass.create { name, displayName, description, frID ->
      organizationTestInstance.errors.reject("error", "error")
      [false, organizationTestInstance]
    }

    controller.organizationService = organizationService
    
    when:
    controller.save()

    then:
    Organization.count() == 0
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.save.failed'

    model.organizationInstance.properties.each {
      it.value == organizationTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from save with invalid workflow or other non instance errors and when valid permission'() {
    setup:
    def organizationService = Mock(aaf.vhr.OrganizationService)

    shiroSubject.isPermitted("app:administrator") >> true

    def organizationTestInstance = Organization.build()
    organizationTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    organizationTestInstance.delete()

    Organization.metaClass.save { null }

    organizationService.metaClass.create { name, displayName, description, frID ->
      [false, organizationTestInstance]
    }

    controller.organizationService = organizationService
    
    when:
    println params
    controller.save()

    then:
    response.status == 500
  }

  def 'ensure correct output from save with valid data and when valid permission'() {
    setup:
    def organizationService = Mock(aaf.vhr.OrganizationService)

    shiroSubject.isPermitted("app:administrator") >> true

    def organizationTestInstance = Organization.build()
    organizationTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    organizationService.metaClass.create { name, displayName, description, frID ->
      [true, organizationTestInstance]
    }

    controller.organizationService = organizationService

    when:
    controller.save()

    then:
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.save.success'

    def savedOrganizationTestInstance = Organization.first()
    savedOrganizationTestInstance.properties.each {
      it.value == organizationTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from edit when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> false

    when:
    params.id = organizationTestInstance.id
    def model = controller.edit()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from edit when valid permission'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true

    when:
    params.id = organizationTestInstance.id
    def model = controller.edit()

    then:
    model.organizationInstance == organizationTestInstance
  }

  def 'ensure correct output from update when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance}.id}:edit") >> false

    when:
    params.id = organizationTestInstance.id
    def model = controller.update()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from update with null version but valid permission'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true
    
    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = null
    controller.update()

    then:
    Organization.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.update.noversion'
  }

  def 'ensure correct output from update with invalid data and when valid permission'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true
    organizationTestInstance.getVersion() >> 20
    
    organizationTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    Organization.metaClass.save { null }
    
    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = 1
    controller.update()

    then:
    Organization.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.update.failed'

    model.organizationInstance.properties.each {
      it.value == organizationTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from update with valid data and when valid permission'() {
    setup:
    def organizationTestInstance = Organization.build(active:true, orgScope:'orgname')
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true
    
    organizationTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = 0
    controller.update()

    then:
    Organization.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.update.success'

    def savedOrganizationTestInstance = Organization.first()
    savedOrganizationTestInstance == organizationTestInstance

    savedOrganizationTestInstance.properties.each {
      it.value == organizationTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from delete when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:delete") >> false

    when:
    params.id = organizationTestInstance.id
    def model = controller.delete()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from delete when valid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administrator") >> true

    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    def model = controller.delete()

    then:
    Organization.count() == 0

    response.redirectedUrl == "/organization/list"

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.delete.success'
  }

  def 'ensure correct output from delete when integrity violation'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administrator") >> true

    Organization.metaClass.delete { throw new org.springframework.dao.DataIntegrityViolationException("Thrown from test case") }

    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    def model = controller.delete()

    then:
    Organization.count() == 1

    response.redirectedUrl == "/organization/show/${organizationTestInstance.id}"

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.delete.failure'
  }

  def 'ensure correct output from toggleActive when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance}.id}:edit") >> false

    when:
    params.id = organizationTestInstance.id
    def model = controller.toggleActive()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleActive with null version but valid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true
    
    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = null
    controller.toggleActive()

    then:
    Organization.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.toggleactive.noversion'
  }

  def 'ensure correct output from toggleActive'() {
    setup:
    def organizationTestInstance = Organization.build(active:false)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true
    
    expect:
    Organization.count() == 1
    !organizationTestInstance.active

    when:
    params.id = organizationTestInstance.id
    params.version = 1
    controller.toggleActive()

    then:
    Organization.count() == 1
    organizationTestInstance.active
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.toggleactive.success'
  }



  def 'ensure correct output from toggleArchive when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administration") >> false

    when:
    def model = controller.toggleArchive()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleArchive with null version but valid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = null
    controller.toggleArchive()

    then:
    Organization.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.togglearchive.noversion'
  }

  def 'ensure correct output from toggleArchive'() {
    setup:
    def organizationTestInstance = Organization.build(active:false)
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Organization.count() == 1
    !organizationTestInstance.archived

    when:
    params.id = organizationTestInstance.id
    params.version = 1
    controller.toggleArchive()

    then:
    Organization.count() == 1
    organizationTestInstance.archived
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.togglearchive.success'
  }




  def 'ensure correct output from toggleBlocked when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administration") >> false

    when:
    def model = controller.toggleBlocked()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleBlocked with null version but valid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Organization.count() == 1

    when:
    params.id = organizationTestInstance.id
    params.version = null
    controller.toggleBlocked()

    then:
    Organization.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.organization.toggleblocked.noversion'
  }

  def 'ensure correct output from toggleBlocked'() {
    setup:
    def organizationTestInstance = Organization.build(active:false)
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Organization.count() == 1
    !organizationTestInstance.blocked

    when:
    params.id = organizationTestInstance.id
    params.version = 1
    controller.toggleBlocked()

    then:
    Organization.count() == 1
    organizationTestInstance.blocked
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.organization.toggleblocked.success'
  }







  def 'ensure correct output from createAccount when invalid permission'() {
    setup:
    def organizationTestInstance = Organization.build()
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance}.id}:edit") >> false

    when:
    params.id = organizationTestInstance.id
    def model = controller.createaccount()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from createAccount'() {
    setup:
    def organizationTestInstance = Organization.build()

    (1..10).each { Group.build(organization:organizationTestInstance)}

    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:edit") >> true

    when:
    params.id = organizationTestInstance.id
    def model = controller.createaccount()

    then:
    model.organizationInstance == organizationTestInstance
    model.groupInstanceList.size() == 10
    model.managedSubjectInstance != null
  }

}

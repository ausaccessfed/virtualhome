package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

import aaf.base.identity.*

@TestFor(aaf.vhr.GroupController)
@Build([ManagedSubject, Organization, Group, aaf.base.identity.Subject, aaf.base.identity.Role, aaf.base.identity.Permission])
class GroupControllerSpec  extends spock.lang.Specification {
  
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
    shiroEnvironment.setSubject(shiroSubject)
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
    def result = controller.validGroup()

    then:
    !result
    response.status == 302

    response.redirectedUrl == "/group/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.group.no.id'
  }

  def 'ensure redirect to list if no valid instance found by beforeInterceptor'() {
    when:
    params.id = 1
    def result = controller.validGroup()

    then:
    !result
    response.status == 302

    response.redirectedUrl== "/group/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.group.notfound'
  }

  def 'ensure true if valid instance found by beforeInterceptor and functioning and not app admin'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:organizationTestInstance, active:true)

    shiroSubject.isPermitted("app:administrator") >> false

    when:
    params.id = groupTestInstance.id
    def result = controller.validGroup()

    then:
    result
  }

  def 'ensure redirect to list if no id presented to validOrganization'() {
    when:
    params.organization = [:]
    def result = controller.validOrganization()

    then:
    !result
    response.status == 302

    response.redirectedUrl == "/group/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.groups.organization.no.id'
  }

  def 'ensure redirect to list if no valid instance found by validOrganization'() {
    when:
    params.organization = [id:1]
    def result = controller.validOrganization()

    then:
    !result
    response.status == 302

    response.redirectedUrl== "/group/list"

    flash.type == 'info'
    flash.message == 'controllers.aaf.vhr.groups.organization.notfound'
  }

  def 'ensure true if valid organization found by validOrganization and functioning'() {
    setup:
    def organization = Organization.build(active:true)

    when:
    params.organization = [id:organization.id]
    def result = controller.validOrganization()

    then:
    result
  }

  def 'ensure correct output from list'() {
    setup:
    (1..10).each { Group.build() }

    when:
    params.max = max
    def model = controller.list()

    then:
    Group.count() == total
    model.groupInstanceList.size() == expectedResult

    where:
    max | total | expectedResult
    0 | 10 | 10
    5 | 10 | 5
  }

  def 'ensure correct output from show'() {
    setup:
    def groupTestInstance = Group.build()

    when:
    params.id = groupTestInstance.id
    def model = controller.show()

    then:
    model.groupInstance == groupTestInstance
  }

  def 'ensure correct output from create when valid permission'() {
    setup:
    def o = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> true

    when:
    params.organization = [id:o.id]
    def model = controller.create()

    then:
    model.groupInstance.instanceOf(Group)
  }

  def 'ensure correct output from create when invalid permission'() {
    def o = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> false

    when:
    params.organization = [id:o.id]
    def model = controller.create()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save when invalid permission'() {
    def o = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> false

    when:
    params.organization = [id:o.id]
    def model = controller.save()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save with invalid data and when valid permission'() {
    setup:
    def o = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> true

    def groupTestInstance = Group.build(organization: o)
    groupTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    groupTestInstance.delete()

    Group.metaClass.save { null }
    
    when:
    controller.save()

    then:
    Group.count() == 0
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.save.failed'

    model.groupInstance.properties.each {
      it.value == groupTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from save with valid data valid permission but licensing violation'() {
    setup:
    def o = Organization.build(groupLimit: 3, active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> true

    (1..3).each { Group.build(organization: o) }

    def groupTestInstance = Group.build(organization: o)
    groupTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    groupTestInstance.delete()

    expect:
    Group.count() == 3
    Role.count() == 0
    Permission.count() == 0

    when:
    controller.save()

    then:
    Group.count() == 3
    Role.count() == 0
    Permission.count() == 0

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.licensing.failed'
  }

  def 'ensure correct output from save with valid data and when valid permission'() {
    setup:
    def o = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:create") >> true

    def groupTestInstance = Group.build(organization: o)
    groupTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    groupTestInstance.delete()

    expect:
    Group.count() == 0
    Role.count() == 0
    Permission.count() == 0

    when:
    controller.save()

    then:
    Group.count() == 1
    Role.count() == 1
    Permission.count() == 1

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.save.success'

    def savedGroupTestInstance = Group.first()
    savedGroupTestInstance.properties.each {
      it.value == groupTestInstance.getProperty(it.key)
    }

    def groupRole = Role.findWhere(name:"group:${savedGroupTestInstance.id}:administrators")
    groupRole.description == "Administrators for the Group ${savedGroupTestInstance.name} of Organization ${savedGroupTestInstance.organization.displayName}"
    groupRole.permissions.size() == 1
    groupRole.permissions.toArray()[0].target == "app:manage:organization:${savedGroupTestInstance.organization.id}:group:${savedGroupTestInstance.id}:*"
  }

  def 'ensure correct output from edit when invalid permission'() {
    setup:
    def groupTestInstance = Group.build()
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.edit()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from edit when valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true

    when:
    params.id = groupTestInstance.id
    def model = controller.edit()

    then:
    model.groupInstance == groupTestInstance
  }

  def 'ensure correct output from update when invalid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.update()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from update with null version but valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true
    
    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = null
    controller.update()

    then:
    Group.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.update.noversion'
  }

  def 'ensure correct output from update with invalid data and when valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true
    groupTestInstance.getVersion() >> 20
    
    groupTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    Group.metaClass.save { null }
    
    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = 1
    controller.update()

    then:
    Group.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.update.failed'

    model.groupInstance.properties.each {
      it.value == groupTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from update with valid data and when valid permission'() {
    setup:
    def groupTestInstance = Group.build(groupScope:'groupname')
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true
    
    groupTestInstance.properties.each {
      if(it.value) {
        if(it.value.hasProperty('id'))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = 0
    controller.update()

    then:
    Group.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.update.success'

    def savedGroupTestInstance = Group.first()
    savedGroupTestInstance == groupTestInstance

    savedGroupTestInstance.properties.each {
      it.value == groupTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from delete when invalid permission'() {
    setup:
    def o = Organization.build()
    o.active = true
    def groupTestInstance = Group.build(organization:o)
    shiroSubject.isPermitted("app:manage:organization:${o.id}:group:delete") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.delete()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from delete when valid permission'() {
    setup:
    def o = Organization.build()
    o.active = true
    def groupTestInstance = Group.build(organization:o)
    shiroSubject.isPermitted("app:administrator") >> true

    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    def model = controller.delete()

    then:
    Group.count() == 0

    response.redirectedUrl == "/organization/show/${o.id}#tab-groups"

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.delete.success'
  }

  def 'ensure correct output from delete when integrity violation'() {
    setup:
    def o = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:o)
    shiroSubject.isPermitted("app:administrator") >> true

    Group.metaClass.delete { throw new org.springframework.dao.DataIntegrityViolationException("Thrown from test case") }

    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    def model = controller.delete()

    then:
    Group.count() == 1

    response.redirectedUrl == "/group/show/${groupTestInstance.id}"

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.delete.failure'
  }

  def 'ensure correct output from toggleActive when invalid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.toggleActive()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleActive with null version but valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true
    
    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = null
    controller.toggleActive()

    then:
    Group.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.toggleactive.noversion'
  }

  def 'ensure correct output from toggleActive'() {
    setup:
    def groupTestInstance = Group.build(active:false)
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:edit") >> true
    
    expect:
    Group.count() == 1
    !groupTestInstance.active

    when:
    params.id = groupTestInstance.id
    params.version = 1
    controller.toggleActive()

    then:
    Group.count() == 1
    groupTestInstance.active
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.toggleactive.success'
  }



  def 'ensure correct output from toggleBlocked when invalid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:admnistration") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.toggleBlocked()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleBlocked with null version but valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = null
    controller.toggleBlocked()

    then:
    Group.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.toggleblocked.noversion'
  }

  def 'ensure correct output from toggleBlocked'() {
    setup:
    def groupTestInstance = Group.build(blocked:false)
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Group.count() == 1
    !groupTestInstance.blocked

    when:
    params.id = groupTestInstance.id
    params.version = 1
    controller.toggleBlocked()

    then:
    Group.count() == 1
    groupTestInstance.blocked
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.toggleblocked.success'
  }

  def 'ensure correct output from toggleArchived when invalid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:admnistration") >> false

    when:
    params.id = groupTestInstance.id
    def model = controller.toggleArchived()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleArchived with null version but valid permission'() {
    setup:
    def groupTestInstance = Group.build()
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Group.count() == 1

    when:
    params.id = groupTestInstance.id
    params.version = null
    controller.toggleArchived()

    then:
    Group.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.group.togglearchived.noversion'
  }

  def 'ensure correct output from toggleArchived'() {
    setup:
    def groupTestInstance = Group.build(archived:false)
    groupTestInstance.organization.active = true
    shiroSubject.isPermitted("app:administration") >> true
    
    expect:
    Group.count() == 1
    !groupTestInstance.archived

    when:
    params.id = groupTestInstance.id
    params.version = 1
    controller.toggleArchived()

    then:
    Group.count() == 1
    groupTestInstance.archived
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.group.togglearchived.success'
  }
}

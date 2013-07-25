package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

import aaf.base.identity.*

@TestFor(aaf.vhr.ManageAdministratorsController)
@Build([Organization, Group, aaf.base.identity.Subject, aaf.base.identity.Role])
@Mock([Role, ManagedSubject])
class ManageAdministratorsControllerSpec extends spock.lang.Specification {
  
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

  def 'ensure validSubject returns valid Subject when input correct'() {
    when:
    params.subjectID = subject.id
    def s = controller.validSubject()

    then:
    s == subject
  }

  def 'ensure validSubject returns 400 when no subjectID supplied'() {
    when:
    def s = controller.validSubject()

    then:
    s == null
    response.status == 400
  }

  def 'ensure validSubject returns 400 when invalid subjectID supplied'() {
    when:
    params.subjectID = 0
    def s = controller.validSubject()

    then:
    s == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns correct Role and Instance when valid org and valid perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == roleTestInstance
    organizationInstance == organizationTestInstance
  }

  def 'ensure validRoleInstance returns 400 when invalid org'() {
    when:
    params.type = 'organization'
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    organizationInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns correct Role and Instance when valid but not functioning org and app:administrator perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:false)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:administrator") >> true
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == roleTestInstance
    organizationInstance == organizationTestInstance
  }

  def 'ensure validRoleInstance returns 400 when valid but not functioning org and not app:administrator perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:false)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:administrator") >> false
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true
    
    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    organizationInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns 403 when valid org but invalid perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> false

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    organizationInstance == null
    response.status == 403
  }

  def 'ensure validRoleInstance returns 400 when valid org and valid perms but non existant admin role'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    def (roleInstance, organizationInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    organizationInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns correct Role when valid group and valid perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:organizationTestInstance, active:true)
    def roleTestInstance = Role.build(name:"group:${groupTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:manage:administrators") >> true

    when:
    params.type = 'group'
    params.id = groupTestInstance.id
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == roleTestInstance
    groupInstance == groupTestInstance
  }

  def 'ensure validRoleInstance returns 400 when invalid group'() {
    when:
    params.type = 'group'
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    groupInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns correct Role when valid but not functioning group and app:administrator perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:organizationTestInstance, active:false)
    def roleTestInstance = Role.build(name:"group:${groupTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:manage:administrators") >> true
    shiroSubject.isPermitted("app:administrator") >> true
    when:
    params.type = 'group'
    params.id = groupTestInstance.id
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == roleTestInstance
    groupInstance == groupTestInstance
  }

  def 'ensure validRoleInstance returns 400 when valid but not functioning group and without app:administrator perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:organizationTestInstance, active:false)
    def roleTestInstance = Role.build(name:"group:${groupTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:manage:administrators") >> true
    shiroSubject.isPermitted("app:administrator") >> false
    when:
    params.type = 'group'
    params.id = groupTestInstance.id
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    groupInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns 403 when valid group but invalid perms'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def groupTestInstance = Group.build(organization:organizationTestInstance, active:true)
    def roleTestInstance = Role.build(name:"group:${groupTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:manage:administrators") >> false

    when:
    params.type = 'group'
    params.id = groupTestInstance.id
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    groupInstance == null
    response.status == 403
  }

  def 'ensure validRoleInstance returns 400 when valid group and valid perms but non existant admin role'() {
    setup:
    def groupTestInstance = Group.build(active:true)
    shiroSubject.isPermitted("app:manage:organization:${groupTestInstance.organization.id}:group:${groupTestInstance.id}:manage:administrators") >> true

    when:
    params.type = 'group'
    params.id = groupTestInstance.id
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    groupInstance == null
    response.status == 400
  }

  def 'ensure validRoleInstance returns 400 when unknown type supplied'() {
    when:
    params.type = 'something'
    def (roleInstance, groupInstance) = controller.validRoleInstance()

    then:
    roleInstance == null
    groupInstance == null
    response.status == 400
  }

  def 'ensure search returns all subjects when no current admins'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    (1..10).each { i ->
      aaf.base.identity.Subject.build(sharedToken:"abcd$i", enabled:true)
    }

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    controller.search()

    then:
    response.text == "count: 10 role:${roleTestInstance.id}"
  }

  def 'ensure search returns subjects that arent current admins'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    (1..10).each { i ->
      aaf.base.identity.Subject.build(sharedToken:"abcd$i", enabled:true)

      if(i < 3) {
        roleTestInstance.addToSubjects(subject)
        subject.addToRoles(roleTestInstance)
        roleTestInstance.save()
      }
    }

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    controller.search()

    then:
    response.text == "count: 10 role:${roleTestInstance.id}"
  }

  def 'ensure valid role/permissions required for search'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> false

    (1..10).each { i ->
      def subject = aaf.base.identity.Subject.build()

      if(i < 3) {
        roleTestInstance.addToSubjects(subject)
        subject.addToRoles(roleTestInstance)
        roleTestInstance.save()
      }
    }

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    controller.search()

    then:
    response.status == 403
  }

  def 'ensure valid role/permissions required for add'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> false

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = subject.id
    controller.add()

    then:
    response.status == 403
  }

  def 'ensure valid target subject required for add'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = -1
    controller.add()

    then:
    response.status == 400
  }

  def 'ensure correct output from add when all input valid'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def targetSubject = aaf.base.identity.Subject.build()
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    (1..10).each { i ->
      def subject = aaf.base.identity.Subject.build()
    }

    views['/templates/manageadministrators/_modifiedadministrators.gsp'] = "role:\${role.id} subject:\${role.subjects.toArray()[0].id}"

    expect:
    targetSubject.roles == null
    roleTestInstance.subjects == null

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = targetSubject.id
    controller.add()

    then:
    targetSubject.roles.size() == 1
    roleTestInstance.subjects.size() == 1
    response.text == "role:${roleTestInstance.id} subject:${targetSubject.id}"
  }

  def 'ensure valid role/permissions required for remove'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> false

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = subject.id
    controller.remove()

    then:
    response.status == 403
  }

  def 'ensure valid target subject required for remove'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    views['/templates/manageadministrators/_search.gsp'] = "count: \${subjects.size()} role:\${role.id}"

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = -1
    controller.remove()

    then:
    response.status == 400
  }

  def 'ensure correct output from delete when all input valid'() {
    setup:
    def organizationTestInstance = Organization.build(active:true)
    def targetSubject = aaf.base.identity.Subject.build()
    def roleTestInstance = Role.build(name:"organization:${organizationTestInstance.id}:administrators")
    shiroSubject.isPermitted("app:manage:organization:${organizationTestInstance.id}:manage:administrators") >> true

    roleTestInstance.addToSubjects(targetSubject)
    targetSubject.addToRoles(roleTestInstance)

    roleTestInstance.save()
    targetSubject.save()

    views['/templates/manageadministrators/_modifiedadministrators.gsp'] = "role:\${role.id} subjects:\${role.subjects.size()}"

    expect:
    targetSubject.roles.size() == 1
    roleTestInstance.subjects.size() == 1

    when:
    params.type = 'organization'
    params.id = organizationTestInstance.id
    params.subjectID = targetSubject.id
    controller.remove()

    then:
    targetSubject.roles.size() == 0
    roleTestInstance.subjects.size() == 0
    response.text == "role:${roleTestInstance.id} subjects:0"
  }

}

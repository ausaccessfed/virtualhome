package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

@TestFor(aaf.vhr.ManagedSubjectController)
@Build([Organization, Group, ManagedSubject, aaf.base.identity.Subject])
@Mock([Organization, Group, ManagedSubject, StateChange])
class ManagedSubjectControllerSpec  extends spock.lang.Specification {
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

  def 'ensure beforeInterceptor only excludes list, create, save, createcsv, savecsv'() {
    when:
    controller

    then:
    controller.beforeInterceptor.except.size() == 5
    controller.beforeInterceptor.except.containsAll(['list', 'create', 'save', 'createcsv', 'savecsv'])
  }

  def 'ensure redirect to list if no ID presented to beforeInterceptor'() {
    when:
    def result = controller.validManagedSubject()

    then:
    !result
    response.status == 404
  }

  def 'ensure redirect to list if no valid instance found by beforeInterceptor'() {
    when:
    params.id = 1
    def result = controller.validManagedSubject()

    then:
    !result
    response.status == 404
  }

  def 'ensure redirect to list if no groupID presented to validGroup'() {
    when:
    params.group = [:]
    def result = controller.validGroup()

    then:
    !result
    response.status == 404
  }

  def 'ensure redirect to list if no valid instance found by validGroup'() {
    when:
    params.group = [id:1]
    def result = controller.validGroup()

    then:
    !result
    response.status == 404
  }

  def 'ensure true if valid group found by validGroup'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)

    when:
    params.group = [id:group.id]
    def result = controller.validGroup()

    then:
    result
  }

  def 'ensure correct output from list'() {
    setup:
    (1..10).each { ManagedSubject.build() }
    shiroSubject.isPermitted("app:administrator") >> true

    when:
    params.max = max
    def model = controller.list()

    then:
    ManagedSubject.count() == total
    model.managedSubjectInstanceList.size() == expectedResult

    where:
    max | total | expectedResult
    0 | 10 | 10
    5 | 10 | 5
  }

  def 'ensure correct output from list without permissions'() {
    setup:
    (1..10).each { ManagedSubject.build() }
    shiroSubject.isPermitted("app:administrator") >> false

    when:
    params.max = max
    def model = controller.list()

    then:
    model == null
    response.status == 403

    where:
    max | total | expectedResult
    0 | 10 | 10
    5 | 10 | 5
  }

  def 'ensure correct output from show'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build()
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:show") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.show()

    then:
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'ensure correct output from show when invalid permission'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build()
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:show") >> false

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.show()

    then:
    response.status == 403
  }

  def 'ensure correct output from create when valid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.create()

    then:
    model.managedSubjectInstance.instanceOf(ManagedSubject)
  }

  def 'ensure correct output from create when invalid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.create()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from createcsv when valid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.createcsv()

    then:
    model.groupInstance.instanceOf(Group)
  }

  def 'ensure correct output from createcsv when invalid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.createcsv()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save when invalid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.save()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from save with invalid data and when valid permission'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    managedSubjectTestInstance.delete()

    ManagedSubject.metaClass.save { null }

    controller.sharedTokenService = sharedTokenService

    when:
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject)

    ManagedSubject.count() == 0
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.validate.failed'

    model.managedSubjectInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from save with valid data and valid permission but licensing violation'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def organization = Organization.build(active:true, subjectLimit:5)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    (1..5).each { ManagedSubject.build(group:group, organization:group.organization) }

    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    managedSubjectTestInstance.delete()

    controller.sharedTokenService = sharedTokenService
    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 5

    when:
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject) >> {ManagedSubject subject -> subject.sharedToken = '1234'}
    0 * managedSubjectService.register(_ as ManagedSubject)>> {ManagedSubject subject -> subject.save()}
    ManagedSubject.count() == 5
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.licensing.failed'
  }

  def 'ensure correct output from save with valid data and when valid permission'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:administrator") >> false
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    def managedSubjectTestInstance = ManagedSubject.buildWithoutSave(group:group, organization:group.organization, accountExpires:null)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    controller.sharedTokenService = sharedTokenService
    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 0

    when:
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject) >> {ManagedSubject subject -> subject.sharedToken = '1234'}
    1 * managedSubjectService.register(_ as ManagedSubject)>> {ManagedSubject subject -> subject.save()}
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.save.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from save with valid data incl entitlements and when valid permission'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:administrator") >> false
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    def managedSubjectTestInstance = ManagedSubject.buildWithoutSave(group:group, organization:group.organization)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    params.eduPersonEntitlement = "some:urn:value\nsome:other:urn:value"

    controller.sharedTokenService = sharedTokenService
    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 0

    when:
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject) >> {ManagedSubject subject -> subject.sharedToken = '1234'}
    1 * managedSubjectService.register(_ as ManagedSubject)>> {ManagedSubject subject -> subject.save()}
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.save.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }

    savedManagedSubjectTestInstance.eduPersonEntitlement == "some:urn:value;some:other:urn:value"
  }

  def 'ensure correct output from save with valid data, multiple eduPersonAffilliation but not saving sharedToken when valid create permission'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:administrator") >> false
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:create") >> true

    def managedSubjectTestInstance = ManagedSubject.buildWithoutSave(group:group, organization:group.organization)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    controller.sharedTokenService = sharedTokenService
    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 0

    when:
    params.eduPersonAffiliation = ['member', 'library-walk-in']
    params.sharedToken = 'abcdefg'
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject) >> {ManagedSubject subject -> subject.sharedToken = '1234'}
    1 * managedSubjectService.register(_ as ManagedSubject)>> {ManagedSubject subject -> subject.save()}
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.save.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
    savedManagedSubjectTestInstance.sharedToken != 'abcdefg'

    savedManagedSubjectTestInstance.eduPersonAffiliation == 'member;library-walk-in'
  }

   def 'ensure correct output from save with valid data specifying sharedToken when administrator'() {
    setup:
    def sharedTokenService = Mock(aaf.vhr.SharedTokenService)
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:administrator") >> true

    def managedSubjectTestInstance = ManagedSubject.buildWithoutSave(group:group, organization:group.organization)
    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    controller.sharedTokenService = sharedTokenService
    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 0

    when:
    params.eduPersonAffiliation = ['member', 'library-walk-in']
    params.sharedToken = 'abcdefg'
    controller.save()

    then:
    1 * sharedTokenService.generate(_ as ManagedSubject) >> {ManagedSubject subject -> subject.sharedToken = '1234'}
    1 * managedSubjectService.register(_ as ManagedSubject)>> {ManagedSubject subject -> subject.save()}
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.save.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
    savedManagedSubjectTestInstance.sharedToken == 'abcdefg'

    savedManagedSubjectTestInstance.eduPersonAffiliation == 'member;library-walk-in'
  }

  def 'ensure correct output from savecsv when invalid permission'() {
    setup:
    def organization = Organization.build(active:true)
    def group = Group.build(organization:organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:create") >> true

    when:
    params.group = [id:group.id]
    def model = controller.savecsv()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from edit when invalid permission'() {
    setup:
    def group = Group.build()
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.edit()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from edit when valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, hash:'0'*60)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.edit()

    then:
    model.managedSubjectInstance == managedSubjectTestInstance
  }

  def 'ensure correct output from update when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.update()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from update when account has no login assigned and non super administrator tries to set one'() {
    setup:
    def group = Group.build(active:true)
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, login:null, archived: false)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 0
    params.login = 'test'
    def model = controller.update()

    then:
    model == null
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.noset.login'
  }

  def 'ensure correct output from update when account has no login assigned and super administrator tries to set one'() {
    setup:
    def group = Group.build(active:true)
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, login:null, archived: false)
    shiroSubject.isPermitted("app:administrator") >> true

    expect:
    managedSubjectTestInstance.login == null

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 0
    params.login = 'test'
    def model = controller.update()

    then:
    model == null
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'
    managedSubjectTestInstance.login == 'test'
  }

  def 'ensure correct output from update with null version but valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = null
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.noversion'
  }

  def 'ensure correct output from update with invalid data and when valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true
    managedSubjectTestInstance.getVersion() >> 20

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }
    ManagedSubject.metaClass.save { null }

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 1
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.failed'

    model.managedSubjectInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from update with valid data and when valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, sharedToken:'abcd1234')
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    ManagedSubject.count() == 1

    when:
    params.sharedToken = 'efgh5678'
    params.id = managedSubjectTestInstance.id
    params.version = 0
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance == managedSubjectTestInstance

    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }

    savedManagedSubjectTestInstance.sharedToken == 'abcd1234'
  }

  def 'ensure correct output from update with valid data and when valid permission for a non-finalized account'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, sharedToken:'abcd1234', login:null)
    shiroSubject.isPermitted('app:administrator') >> true

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    ManagedSubject.count() == 1

    when:
    params.sharedToken = 'efgh5678'
    params.id = managedSubjectTestInstance.id
    params.version = 0
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance == managedSubjectTestInstance

    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }
  }

  def 'ensure correct output from update with valid data including entitlements and when valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, sharedToken:'abcd1234', eduPersonEntitlement:'initial:urn;initial:urn:2')
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    ManagedSubject.count() == 1
    managedSubjectTestInstance.eduPersonEntitlement == 'initial:urn;initial:urn:2'

    when:
    params.eduPersonEntitlement = "some:urn:value\nsome:other:urn:value"
    params.sharedToken = 'efgh5678'
    params.id = managedSubjectTestInstance.id
    params.version = 0
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance == managedSubjectTestInstance

    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }

    savedManagedSubjectTestInstance.sharedToken == 'abcd1234'
    managedSubjectTestInstance.eduPersonEntitlement == 'some:urn:value;some:other:urn:value'
  }


  def 'ensure correct output from update with valid data containing multiple eduPersonAffiliation and when valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, sharedToken:'abcd1234', eduPersonAffiliation:'employee')
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    ManagedSubject.count() == 1

    when:
    params.sharedToken = 'efgh5678'
    params.id = managedSubjectTestInstance.id
    params.version = 0
    params.eduPersonAffiliation = ['member', 'library-walk-in']
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance == managedSubjectTestInstance

    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }

    savedManagedSubjectTestInstance.sharedToken == 'abcd1234'
    savedManagedSubjectTestInstance.eduPersonAffiliation == 'member;library-walk-in'
  }

  def 'ensure correct output from update including sharedToken update with valid data and when super admin'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, sharedToken:'abcd1234')
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true
    shiroSubject.isPermitted("app:administrator") >> true

    managedSubjectTestInstance.properties.each {
      if(it.value) {
        if(grailsApplication.isDomainClass(it.value.getClass()))
          params."${it.key}" = [id:"${it.value.id}"]
        else
          params."${it.key}" = "${it.value}"
      }
    }

    expect:
    ManagedSubject.count() == 1

    when:
    params.sharedToken = 'efgh5678'
    params.id = managedSubjectTestInstance.id
    params.version = 0
    controller.update()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.update.success'

    def savedManagedSubjectTestInstance = ManagedSubject.first()
    savedManagedSubjectTestInstance == managedSubjectTestInstance

    savedManagedSubjectTestInstance.properties.each {
      it.value == managedSubjectTestInstance.getProperty(it.key)
    }

    savedManagedSubjectTestInstance.sharedToken == 'efgh5678'
  }

  def 'ensure correct output from delete when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:delete") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.delete()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from delete when valid permission'() {
    setup:
    def group = Group.build()
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:administrator") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.delete()

    then:
    ManagedSubject.count() == 0

    response.redirectedUrl == "/group/show/${group.id}#tab-accounts"

    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.delete.success'
  }

  def 'ensure correct output from delete when integrity violation'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:administrator") >> true

    ManagedSubject.metaClass.delete { throw new org.springframework.dao.DataIntegrityViolationException("Thrown from test case") }

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.delete()

    then:
    ManagedSubject.count() == 1

    response.redirectedUrl == "/managedSubject/show/${managedSubjectTestInstance.id}"

    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.delete.failure'
  }

  def 'ensure correct output from resend when invalid permission'() {
    setup:
    def group = Group.build()
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id + 1}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.resend()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from resend with valid data and when valid permission'() {
    setup:
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${group.organization.id}:group:${group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    controller.managedSubjectService = managedSubjectService

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    controller.resend()

    then:
    ManagedSubject.count() == 1
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.resend.success'

    1 * managedSubjectService.sendConfirmation(_ as ManagedSubject)
  }

  def 'ensure correct output from togglelock when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> false

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.toggleLock()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleLock with null version but valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = null
    controller.toggleLock()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.togglelock.noversion'
  }

  def 'ensure correct output from toggleLock with valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(locked:true, group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1
    managedSubjectTestInstance.locked

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 1
    controller.toggleLock()
    managedSubjectTestInstance.refresh()

    then:
    !managedSubjectTestInstance.locked
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.togglelock.success'
  }

  def 'ensure correct output from toggleblock when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:administration") >> false

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.toggleBlock()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleBlock with null version but valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:administration") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = null
    controller.toggleBlock()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.toggleblock.noversion'
  }

  def 'ensure correct output from toggleBlock with valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(blocked:true, group:group, organization:group.organization)
    shiroSubject.isPermitted("app:administration") >> true

    expect:
    ManagedSubject.count() == 1
    managedSubjectTestInstance.blocked

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 1
    controller.toggleBlock()
    managedSubjectTestInstance.refresh()

    then:
    !managedSubjectTestInstance.blocked
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.toggleblock.success'
  }

  def 'ensure correct output from toggleActive when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> false

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.toggleActive()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleActive with null version but valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = null
    controller.toggleActive()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.toggleactive.noversion'
  }

  def 'ensure correct output from toggleActive with valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(active:false, group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1
    !managedSubjectTestInstance.active

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 1
    controller.toggleActive()
    managedSubjectTestInstance.refresh()

    then:
    managedSubjectTestInstance.active
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.toggleactive.success'
  }

    def 'ensure correct output from toggleArchive when invalid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> false

    when:
    params.id = managedSubjectTestInstance.id
    def model = controller.toggleArchive()

    then:
    model == null
    response.status == 403
  }

  def 'ensure correct output from toggleArchive with null version but valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1

    when:
    params.id = managedSubjectTestInstance.id
    params.version = null
    controller.toggleArchive()

    then:
    ManagedSubject.count() == 1
    flash.type == 'error'
    flash.message == 'controllers.aaf.vhr.managedsubject.togglearchive.noversion'
  }

  def 'ensure correct output from toggleArchive with valid permission'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(archived:false, group:group, organization:group.organization)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1
    !managedSubjectTestInstance.archived

    when:
    params.id = managedSubjectTestInstance.id
    params.version = 1
    controller.toggleArchive()
    managedSubjectTestInstance.refresh()

    then:
    managedSubjectTestInstance.archived
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.togglearchive.success'
  }

  def 'ensure correct output from resettwosteplogin'() {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, totpKey:'1234')
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1
    managedSubjectTestInstance.totpKey == '1234'

    when:
    params.id = managedSubjectTestInstance.id
    controller.resettwosteplogin(managedSubjectTestInstance.id)

    then:
    managedSubjectTestInstance.totpKey == null
    flash.type == 'success'
    flash.message == 'controllers.aaf.vhr.managedsubject.resettwosteplogin.success'
  }

  def 'ensure correct output from enforcetwosteplogin'()  {
    setup:
    def group = Group.build()
    group.organization.active = true
    def managedSubjectTestInstance = ManagedSubject.build(group:group, organization:group.organization, totpKey:'1234', totpForce: !enforce)
    shiroSubject.isPermitted("app:manage:organization:${managedSubjectTestInstance.organization.id}:group:${managedSubjectTestInstance.group.id}:managedsubject:${managedSubjectTestInstance.id}:edit") >> true

    expect:
    ManagedSubject.count() == 1
    managedSubjectTestInstance.totpKey == '1234'
    managedSubjectTestInstance.totpForce == !enforce

    when:
    params.id = managedSubjectTestInstance.id
    controller.enforcetwosteplogin(managedSubjectTestInstance.id, enforce)

    then:
    managedSubjectTestInstance.totpKey == '1234'
    managedSubjectTestInstance.totpForce == enforce
    flash.type == 'success'
    flash.message == message

    where:
    enforce << [true, false]
    message << ['controllers.aaf.vhr.managedsubject.enforcetwosteplogin.enable.success', 'controllers.aaf.vhr.managedsubject.enforcetwosteplogin.disable.success']
  }
}







package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

import aaf.base.identity.*

@TestFor(aaf.vhr.DashboardController)
@Build([aaf.vhr.Organization, aaf.vhr.Group, aaf.vhr.ManagedSubject, aaf.base.identity.Subject, aaf.base.identity.Role])
@Mock([Organization, Group])
class DashboardControllerSpec extends spock.lang.Specification {
  
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

    aaf.base.identity.SessionRecord.metaClass.'static'.executeQuery = {String q, Map params -> [] as List}
  }

  def 'ensure subject with no organization or group roles has minimal dashboard provided'() {
    when:
    def model = controller.dashboard()

    then:
    model.organizations == null
    model.groups == null
  }

  def 'ensure subject administering an organization has correct data supplied'() {
    setup:
    def o = Organization.build()
    def r = Role.build(name:"organization:${o.id}:adminsters")
    
    subject.addToRoles(r)
    subject.save()

    when:
    def model = controller.dashboard()

    then:
    model.organizationInstanceList != null
    model.organizationInstanceList.size() == 1
    model.organizationInstanceList[0] == o

    model.groupInstanceList != null
    model.groupInstanceList.size() == 0
  }

  def 'ensure subject administering multiple organizations have correct data supplied'() {
    setup:
    (1..10).each {
      def o = Organization.build()
      def r = Role.build(name:"organization:${o.id}:adminsters")

      subject.addToRoles(r)
      subject.save()
    }

    (1..10).each {
      def o = Organization.build()
      def r = Role.build(name:"organization:${o.id}:adminsters")
    }

    expect:
    Organization.count() == 20
    Role.count() == 20
    
    when:
    def model = controller.dashboard()

    then:
    model.organizationInstanceList != null
    model.organizationInstanceList.size() == 10

    model.groupInstanceList != null
    model.groupInstanceList.size() == 0
  }

  def 'ensure subject administering a group has correct data supplied'() {
    setup:
    def g = Group.build()
    def r = Role.build(name:"group:${g.id}:adminsters")
    
    subject.addToRoles(r)
    subject.save()

    when:
    def model = controller.dashboard()

    then:
    model.organizationInstanceList != null
    model.organizationInstanceList.size() == 0

    model.groupInstanceList != null
    model.groupInstanceList.size() == 1
    model.groupInstanceList."${g.organization.displayName}"[0] == g
  }

  def 'ensure subject administering multiple groups has correct data supplied'() {
    setup:
    def organizationTestInstance = Organization.build()

    (1..10).each {
      def g = Group.build(organization:organizationTestInstance)
      def r = Role.build(name:"group:${g.id}:adminsters")
      
      subject.addToRoles(r)
      subject.save()
    }

    (1..10).each {
      def g = Group.build()
      def r = Role.build(name:"group:${g.id}:adminsters")
    }

    when:
    def model = controller.dashboard()

    then:
    model.organizationInstanceList != null
    model.organizationInstanceList.size() == 0

    model.groupInstanceList != null
    model.groupInstanceList.size() == 1
    model.groupInstanceList."${organizationTestInstance.displayName}".size() == 10
  }

  def 'ensure statistics are correctly populated'() {
    setup:
    (1..10).each {
      ManagedSubject.build()
    }
    (1..10).each {
      def g = Group.build()
      def r = Role.build(name:"group:${g.id}:adminsters")
      
      subject.addToRoles(r)
      subject.save()
    }
    (1..10).each {
      def g = Group.build()
      def r = Role.build(name:"group:${g.id}:adminsters")
    }
    (1..10).each {
      def o = Organization.build()
      def r = Role.build(name:"organization:${o.id}:adminsters")

      subject.addToRoles(r)
      subject.save()
    }
    (1..10).each {
      def o = Organization.build()
      def r = Role.build(name:"organization:${o.id}:adminsters")
    }

    aaf.base.identity.SessionRecord.metaClass.'static'.executeQuery = {String q, Map params -> [13,20] as List}

    when:
    def model = controller.dashboard()

    then:
    model.organizationInstanceList != null
    model.organizationInstanceList.size() == 10

    model.groupInstanceList != null

    model.statistics.organizations == 50    // each 1..10 creates unique org
    model.statistics.groups == 30           // Managed Subject Build creates group plus 2 * 1..10 creating Groups
    model.statistics.managedSubjects == 10

    model.statistics.last12MonthSessions.size() == 12
    model.statistics.last12MonthSessions[10] == 13
    model.statistics.last12MonthSessions[11] == 20

  }

}

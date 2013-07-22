package aaf.vhr

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import test.shared.ShiroEnvironment

import aaf.base.identity.*

@TestFor(aaf.vhr.FinalizationController)
@Build([ManagedSubject, ManagedSubjectInvitation, aaf.base.identity.Subject, aaf.base.identity.Role, aaf.base.identity.Permission])
@Mock([Organization, Group])
class FinalizationControllerSpec  extends spock.lang.Specification {
  
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

  def 'ensure invalid invitation instance gives error response'() {
    when:
    params.inviteCode = "invalidcode"
    controller.index()

    then:
    response.redirectedUrl == "/finalization/error"
  }

  def 'ensure utilised invitation redirects to used action'() {
    setup:
    def inv = ManagedSubjectInvitation.build(utilized:true)

    when:
    params.inviteCode = inv.inviteCode
    controller.index()

    then:
    response.redirectedUrl == "/finalization/used"
  }

  def 'ensure valid invitation passes to view'() {
    setup:
    def inv = ManagedSubjectInvitation.build(utilized:false)

    when:
    params.inviteCode = inv.inviteCode
    def model = controller.index()

    then:
    model.managedSubjectInstance == inv.managedSubject
    model.invitationInstance == inv
  }

  def 'ensure login available returns false if username contains space'() {
    when:
    params.login = "test username"
    controller.loginAvailable()

    then:
    controller.response.contentAsString == "false"
  }

  def 'ensure login available returns false if username exists'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login:'testusername')

    when:
    params.login = "testusername"
    controller.loginAvailable()

    then:
    controller.response.contentAsString == "false"
  }

  def 'ensure login available returns true if username available'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build(login:'testusername')

    when:
    params.login = "myusername"
    controller.loginAvailable()

    then:
    controller.response.contentAsString == "true"
  }

  def 'ensure invalid invitation returns error view when completing finalization'() {
    when:
    params.inviteCode = "invalidcode"
    controller.complete()

    then:
    response.redirectedUrl == "/finalization/error"
  }

  def 'ensure fault in ManagedSubjectService renders index again for user to fix errors'() {
    setup:
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def managedSubjectTestInstance = ManagedSubject.build(login:'testuser', mobileNumber:'0413123456')
    def inv = ManagedSubjectInvitation.build(utilized:false, managedSubject:managedSubjectTestInstance)

    controller.managedSubjectService = managedSubjectService

    when:
    params.inviteCode = inv.inviteCode
    params.login = managedSubjectTestInstance.login
    params.plainPassword = 'password'
    params.plainPasswordConfirmation = 'password'
    params.mobileNumber = managedSubjectTestInstance.mobileNumber

    controller.complete()

    then:
    1 * managedSubjectService.finalize(_ as ManagedSubjectInvitation, _ as String, _ as String, _ as String, _ as String) >>> [[false, managedSubjectTestInstance]]
    model.managedSubjectInstance == managedSubjectTestInstance
    model.invitationInstance == inv
    view == "/finalization/index"
  }

def 'ensure successful complete provides complete view'() {
    setup:
    def managedSubjectService = Mock(aaf.vhr.ManagedSubjectService)
    def managedSubjectTestInstance = ManagedSubject.build(login:'testuser', mobileNumber:'0413123456')
    def inv = ManagedSubjectInvitation.build(utilized:false, managedSubject:managedSubjectTestInstance)

    controller.managedSubjectService = managedSubjectService

    when:
    params.inviteCode = inv.inviteCode
    params.login = managedSubjectTestInstance.login
    params.plainPassword = 'password'
    params.plainPasswordConfirmation = 'password'
    params.mobileNumber = managedSubjectTestInstance.mobileNumber

    controller.complete()

    then:
    1 * managedSubjectService.finalize(_ as ManagedSubjectInvitation, _ as String, _ as String, _ as String, _ as String) >>> [[true, managedSubjectTestInstance]]
    response.status == 200
  }

}

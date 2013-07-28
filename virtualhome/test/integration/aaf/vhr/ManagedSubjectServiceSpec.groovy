package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*
import com.icegreen.greenmail.util.*

import aaf.base.admin.EmailTemplate
import aaf.base.identity.Permission
import javax.mail.Message

import groovy.time.TimeCategory

class ManagedSubjectServiceSpec extends IntegrationSpec {
  
  def managedSubjectService
  def greenMail
  def cryptoService

  def grailsApplication
  def subject
  def role

  def setup() {
    role = new aaf.base.identity.Role(name:'allsubjects')
    subject = aaf.base.identity.Subject.build(principal:'http://idp.test.com/entity!http://sp.test.com/entity!1234', cn:'test subject', email:'testsubject@test.com', sharedToken:'1234sharedtoken')
    subject.save()
    subject.errors.each { println it }
    
    assert !subject.hasErrors()

    role.addToSubjects(subject)
    role.save()
    role.errors.each { println it }

    assert !role.hasErrors()

    SpecHelpers.setupShiroEnv(subject)

    grailsApplication.config.aaf.vhr.sharedtoken.idp_entityid="https://test.server.com/idp"
    grailsApplication.config.aaf.vhr.sharedtoken.sha_rounds=2048
    grailsApplication.config.aaf.vhr.crypto.log_rounds = 4
    grailsApplication.config.aaf.vhr.crypto.sha_rounds = 2048
  }

  def cleanup() {
    greenMail.deleteAllMessages()
  }

  def 'ensure successful finalize for ManagedSubject'() {
    setup:
    def o = Organization.build(active: true)
    def g = Group.build(active:true, organization: o)
    def ms = ManagedSubject.build(login:null, hash:null, organization:o, group:g, active:false)
    def inv = ManagedSubjectInvitation.build(managedSubject: ms)

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    !ms.functioning()
    !ms.finalized
    ms.login == null
    ms.hash == null
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, managedSubject) = managedSubjectService.finalize(inv, 'usert', 'thisisalongpasswordtotest', 'thisisalongpasswordtotest', '0413123456')
    def invitation = ManagedSubjectInvitation.get(inv.id)

    then:
    result
    invitation.utilized
    managedSubject != null
    managedSubject.hasErrors() == false
    managedSubject.login == 'usert'
    managedSubject.mobileNumber == '+61413123456'
    cryptoService.verifyPasswordHash('thisisalongpasswordtotest', managedSubject)
    ms.finalized
    ms.functioning()
  }

  def 'ensure successful finalize for ManagedSubject with no mobile'() {
    setup:
    def o = Organization.build(active: true)
    def g = Group.build(active:true, organization: o)
    def ms = ManagedSubject.build(login:null, hash:null, organization:o, group:g, active:false)
    def inv = ManagedSubjectInvitation.build(managedSubject: ms)

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    !ms.functioning()
    ms.login == null
    ms.hash == null
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, managedSubject) = managedSubjectService.finalize(inv, 'usert', 'thisisalongpasswordtotest', 'thisisalongpasswordtotest', null)
    def invitation = ManagedSubjectInvitation.get(inv.id)

    then:
    result
    invitation.utilized
    managedSubject != null
    managedSubject.hasErrors() == false
    managedSubject.login == 'usert'
    managedSubject.mobileNumber == null
    cryptoService.verifyPasswordHash('thisisalongpasswordtotest', managedSubject)
    ms.functioning()
  }

  def 'ensure failed finalize for ManagedSubject with poor password'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)
    def ms = ManagedSubject.build(organization:o, group:g, login:null)
    def inv = new ManagedSubjectInvitation(managedSubject: ms).save()

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, managedSubject) = managedSubjectService.finalize(inv, 'usert', 'insecurepw', 'insecurepw', '0413123456')
    inv.refresh()

    then:
    !result
    !inv.utilized
    managedSubject != null
    managedSubject.hasErrors()
    managedSubject.login == 'usert'
    managedSubject.hash == null
  }

  def 'ensure failed finalize for ManagedSubject that has already undertaken the process'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)
    def ms = ManagedSubject.build(organization:o, group:g, login:'mylogin')
    def inv = new ManagedSubjectInvitation(managedSubject: ms).save()

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, error) = managedSubjectService.finalize(inv, 'usert', 'insecurepw', 'insecurepw', '0413123456')
    inv.refresh()

    then:
    !result
    error == "The invitation code that is attempting to be claimed is invalid"
  }

  def 'ensure failed finalize for ManagedSubject that has no unutilized invite'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)
    def ms = ManagedSubject.build(organization:o, group:g, login:'mylogin')
    def inv = new ManagedSubjectInvitation(managedSubject: ms, utilized:true).save()

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, error) = managedSubjectService.finalize(inv, 'usert', 'insecurepw', 'insecurepw', '0413123456')
    inv.refresh()

    then:
    !result
    error == "The invitation code that is attempting to be claimed is invalid"
  }

  def 'ensure failed finalize for ManagedSubject with non matching password'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)
    def ms = ManagedSubject.build(organization:o, group:g, login:null)
    def inv = ManagedSubjectInvitation.build(managedSubject: ms)

    expect:
    ManagedSubject.count() == 1
    ManagedSubjectInvitation.count() == 1
    o.subjects.size() == 1
    g.subjects.size() == 1

    when:
    def (result, managedSubject) = managedSubjectService.finalize(inv, 'usert', 'inzecurepW1!', 'inzecurepW1', '0413123456')
    inv.refresh()

    then:
    !result
    !inv.utilized
    managedSubject != null
    managedSubject.hasErrors()
    managedSubject.login == 'usert'
    managedSubject.hash == null
  }

  def 'ensure register creates new ManagedSubject'() {
    setup:
    def o = Organization.build(active:true)
    def g = Group.build(organization: o, active:true)
    def et = new EmailTemplate(name:'registered_managed_subject', content: 'This is an email for ${managedSubject.cn} telling them to come and complete registration with code ${invitation.inviteCode}').save()
    
    def managedSubjectTestInstance = ManagedSubject.buildWithoutSave(organization:o, group:g)

    when:  
    def managedSubject = managedSubjectService.register(managedSubjectTestInstance)
    o.refresh()
    g.refresh()

    then:
    managedSubject != null
    !managedSubject.functioning()

    ManagedSubject.count() == 1
    managedSubject.cn == managedSubjectTestInstance.cn
    managedSubject.email == managedSubjectTestInstance.email
    !managedSubject.active
    managedSubject.eduPersonAffiliation == managedSubjectTestInstance.eduPersonAffiliation

    greenMail.getReceivedMessages().length == 1

    def message = greenMail.getReceivedMessages()[0]
    message.subject == 'Action Required: Your new AAF Virtual Home account is almost ready!'
    GreenMailUtil.getBody(message).contains("This is an email for ${managedSubject.cn} telling them")
    GreenMailUtil.getAddressList(message.getRecipients(Message.RecipientType.TO)) == managedSubject.email

    managedSubject.organization == o
    managedSubject.group == g
  }

  def 'ensure invalid CSV lines are rejected correctly (no admin rights)'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)

    expect:
    ManagedSubject.count() == 0

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)

    then:
    !result
    println errors
    errors.size() == expectedErrorCount
    linesProcessed == expectedLinesProcessed
    subjects == null

    ManagedSubject.count() == 0

    where:
    expectedErrorCount | expectedLinesProcessed | csv
    1 | 2 | "Test User,testuser@testdomain.com,staff,rubbish\nTest User,testuser2@testdomain.com,staff,0"
    1 | 2 | "Mr Test User,testuser@testdomain.com,staff,0\nTest User,testuser2@testdomain.com,staff,0"
    3 | 3 | "Test User,testuser@testdomain.com,staff,0\nMr Test User,testuser2@testdomain.com,staff,rubbish\nTest User,testuser3@testdomain.com,staff,"
    3 | 3 | "Test,testuser@testdomain.com,staff,\nMr Test User,testuser2@testdomain.com,staff,hello\nTest User,testuser3@testdomain.com,staff,0"
    2 | 3 | "Test User,testuser@testdomain.com,staff,rubbish\nTest User,testuser2@testdomain.com,staff,0\nTest User2,testuser3@testdomain.com,staff,0,testuser2,password"
  }

  def 'ensure invalid CSV lines are rejected correctly (admin rights)'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)

    subject.permissions = []
    subject.permissions.add(Permission.build(target:"app:administrator"))

    expect:
    ManagedSubject.count() == 0

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)

    then:
    !result

    errors.size() == expectedErrorCount
    linesProcessed == expectedLinesProcessed
    subjects == null

    ManagedSubject.count() == 0

    where:
    expectedErrorCount | expectedLinesProcessed | csv
    1 | 2 | "Test User,testuser@testdomain.com,staff,rubbish,username,password\nTest User,testuser2@testdomain.com,staff,0"
    1 | 2 | "Mr Test User,testuser@testdomain.com,staff,0\nTest User,testuser2@testdomain.com,staff,0"
    3 | 3 | "Test User,testuser@testdomain.com,staff,0,password\nMr Test User2,testuser2@testdomain.com,staff,rubbish,username\nTest User,testuser3@testdomain.com,staff,"
    3 | 3 | "Test,testuser@testdomain.com,staff,\nMr Test User3,testuser2@testdomain.com,staff,hello,,password\nTest User,testuser3@testdomain.com,staff,0"
    1 | 3 | "Test User,testuser@testdomain.com,staff,rubbish\nTest User,testuser2@testdomain.com,staff,0\nTest User2,testuser3@testdomain.com,staff,0,testuser2,password"
  }

  def 'ensure CSV lines cause account conflicts are rejected correctly'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)
    def ms = ManagedSubject.build(cn:'Test User', email:'testuser@testdomain.com', eduPersonAffiliation:'member')

    String csv = "Test User,testuser@testdomain.com,member,0\nTest User2,testuser2@testdomain.com,staff,12"

    expect:
    ManagedSubject.count() == 1

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)

    then:
    !result
    errors.size() == 0
    subjects.size() == 2
    linesProcessed == 2

    subjects[0].hasErrors()
    !subjects[1].hasErrors()
  }

  def 'ensure CSV lines which conflict with other CSV lines are rejected correctly'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)

    String csv = "Test User,testuser@testdomain.com,member,0\nTest User2,testuser@testdomain.com,staff,12"

    expect:
    ManagedSubject.count() == 0

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)

    then:
    !result
    errors.size() == 1
    errors[0] =~ /email address was already used/
    subjects == null
    linesProcessed == 2
  }

  def 'ensure CSV lines for admin with invalid password are rejected correctly'() {
    setup:
    def o = Organization.build()
    def g = Group.build(organization: o)

    String csv = "Test User,testuser@testdomain.com,member,0,username,password\nTest User2,testuser2@testdomain.com,staff,12,username2,password2"

    subject.permissions = []
    subject.permissions.add(Permission.build(target:"app:administrator"))

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)

    then:
    !result
    ManagedSubject.count() == 0
    errors.size() == 0
    subjects.size() == 2
    linesProcessed == 2

    subjects[0].hasErrors()
    subjects[0].errors['plainPassword']

    subjects[1].hasErrors()
    subjects[1].errors['plainPassword']
  }

  def 'ensure valid CSV creates new ManagedSubject from each line'() {
    setup:
    def o = Organization.build(active:true)
    def g = Group.build(organization: o, active:true)
    def et = new EmailTemplate(name:'registered_managed_subject', content: 'This is an email for ${managedSubject.cn} telling them to come and complete registration with code ${invitation.inviteCode}').save()
    
    expect:
    ManagedSubject.count() == 0
    o.subjects == null
    g.subjects == null

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)
    o.refresh()
    g.refresh()

    then:
    result
    errors.size() == expectedErrorCount
    linesProcessed == expectedLinesProcessed
    subjects.size() == expectedLinesProcessed

    ManagedSubject.count() == expectedLinesProcessed
    !subjects[0].functioning()
    subjects[0].cn == "Test User"
    subjects[0].email == "testuser@testdomain.com"
    !subjects[0].active
    subjects[0].eduPersonAffiliation == "student"
    subjects[0].organization == o
    subjects[0].group == g
    subjects[0].accountExpires == null

    !subjects[1].functioning()
    subjects[1].cn == "Test User2"
    subjects[1].email == "testuser2@testdomain.com"
    !subjects[1].active
    subjects[1].eduPersonAffiliation == "staff"
    subjects[1].organization == o
    subjects[1].group == g

    
    Date now = new Date()
    subjects[1].accountExpires.format('yyyy-MM-dd') == use(TimeCategory) {now + 12.months}.format('yyyy-MM-dd')
    

    greenMail.getReceivedMessages().length == expectedLinesProcessed

    def message = greenMail.getReceivedMessages()[0]
    message.subject == 'Action Required: Your new AAF Virtual Home account is almost ready!'
    GreenMailUtil.getBody(message).contains('This is an email for Test User telling them')
    GreenMailUtil.getAddressList(message.getRecipients(Message.RecipientType.TO)) == 'testuser@testdomain.com'

    def message2 = greenMail.getReceivedMessages()[1]
    message2.subject == 'Action Required: Your new AAF Virtual Home account is almost ready!'
    GreenMailUtil.getBody(message2).contains('This is an email for Test User2 telling them')
    GreenMailUtil.getAddressList(message2.getRecipients(Message.RecipientType.TO)) == 'testuser2@testdomain.com'


    where:
    expectedErrorCount | expectedLinesProcessed | csv
    0 | 2 | "Test User,testuser@testdomain.com,student,0\nTest User2,testuser2@testdomain.com,staff,12"
  }

  def 'ensure valid CSV creates new ManagedSubject from each line for admins'() {
    setup:
    def o = Organization.build(active:true)
    def g = Group.build(organization: o, active:true)
    def et = new EmailTemplate(name:'registered_managed_subject', content: 'This is an email for ${managedSubject.cn} telling them to come and complete registration with code ${invitation.inviteCode}').save()
    
    subject.permissions = []
    subject.permissions.add(Permission.build(target:"app:administrator"))

    expect:
    ManagedSubject.count() == 0
    o.subjects == null
    g.subjects == null

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)
    o.refresh()
    g.refresh()

    then:
    result
    errors.size() == expectedErrorCount
    linesProcessed == expectedLinesProcessed
    subjects.size() == expectedLinesProcessed

    ManagedSubject.count() == expectedLinesProcessed
    subjects[0].cn == "Test User"
    subjects[0].email == "testuser@testdomain.com"
    subjects[0].eduPersonAffiliation == "student"
    subjects[0].organization == o
    subjects[0].group == g
    subjects[0].accountExpires == null
    subjects[0].login == 'username'
    cryptoService.verifyPasswordHash('T0day123!', subjects[0])
    subjects[0].functioning()
    subjects[0].canLogin()

    subjects[1].cn == "Test User2"
    subjects[1].email == "testuser2@testdomain.com"
    subjects[1].eduPersonAffiliation == "staff"
    subjects[1].organization == o
    subjects[1].group == g
    subjects[1].login == 'username2'
    cryptoService.verifyPasswordHash('T0day456!', subjects[1])
    subjects[1].functioning()
    subjects[1].canLogin()

    
    Date now = new Date()
    subjects[1].accountExpires.format('yyyy-MM-dd') == use(TimeCategory) {now + 12.months}.format('yyyy-MM-dd')
    
    greenMail.getReceivedMessages().length == 0

    where:
    expectedErrorCount | expectedLinesProcessed | csv
    0 | 2 | "Test User,testuser@testdomain.com,student,0,username,T0day123!\nTest User2,testuser2@testdomain.com,staff,12,username2,T0day456!"
  }

  def 'ensure valid CSV creates new ManagedSubject without password from each line for admins'() {
    setup:
    def o = Organization.build(active:true)
    def g = Group.build(organization: o, active:true)
    def et = new EmailTemplate(name:'registered_managed_subject', content: 'This is an email for ${managedSubject.cn} telling them to come and complete registration with code ${invitation.inviteCode}').save()

    subject.permissions = []
    subject.permissions.add(Permission.build(target:"app:administrator"))

    expect:
    ManagedSubject.count() == 0
    o.subjects == null
    g.subjects == null

    when:
    def (result, errors, subjects, linesProcessed) = managedSubjectService.registerFromCSV(g, csv.bytes)
    o.refresh()
    g.refresh()

    then:
    result
    errors.size() == expectedErrorCount
    linesProcessed == expectedLinesProcessed
    subjects.size() == expectedLinesProcessed

    ManagedSubject.count() == expectedLinesProcessed
    subjects[0].cn == "Test User"
    subjects[0].email == "testuser@testdomain.com"
    subjects[0].eduPersonAffiliation == "student"
    subjects[0].organization == o
    subjects[0].group == g
    subjects[0].accountExpires == null
    subjects[0].login == 'username'
    subjects[0].hash == null
    !subjects[0].finalized

    subjects[1].cn == "Test User2"
    subjects[1].email == "testuser2@testdomain.com"
    subjects[1].eduPersonAffiliation == "staff"
    subjects[1].organization == o
    subjects[1].group == g
    subjects[1].login == 'username2'
    subjects[1].hash == null
    !subjects[1].finalized


    Date now = new Date()
    subjects[1].accountExpires.format('yyyy-MM-dd') == use(TimeCategory) {now + 12.months}.format('yyyy-MM-dd')

    greenMail.getReceivedMessages().length == expectedLinesProcessed

    where:
    expectedErrorCount | expectedLinesProcessed | csv
    0 | 2 | "Test User,testuser@testdomain.com,student,0,username\nTest User2,testuser2@testdomain.com,staff,12,username2"
  }

}

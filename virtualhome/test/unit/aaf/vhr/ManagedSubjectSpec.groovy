package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

import test.shared.ShiroEnvironment

@TestFor(aaf.vhr.ManagedSubject)
@Build([ManagedSubject, Organization, Group, ChallengeResponse])
@Mock([ManagedSubject, Organization, Group, ChallengeResponse, StateChange])
class ManagedSubjectSpec extends spock.lang.Specification  {

  @Shared def shiroEnvironment = new ShiroEnvironment()

  org.apache.shiro.subject.Subject shiroSubject
  
  def cleanupSpec() { 
    shiroEnvironment.tearDownShiro() 
  }

  def setup() {
    shiroSubject = Mock(org.apache.shiro.subject.Subject)
    shiroEnvironment.setSubject(shiroSubject)
  }

  def 'ensure login can be null'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()
    s.login != null

    when:
    s.login = null

    then:
    s.save()
  }

  def 'ensure login must not be blank'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.login = val

    then:
    !s.save()
    reason == s.errors['login']

    where:
    val << ['']
    reason << ['blank']
  }

  def 'ensure login must be unique'() {
    setup:
    def s = ManagedSubject.build()
    def s2 = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()
    s2.validate()

    when:
    s.login = s2.login

    then:
    !s.save()
    'unique' == s.errors['login']
  }

  def 'ensure subject stores attribute values'() {
    setup:
    def s = ManagedSubject.build()

    expect:
    s.save()

    when:
    s.telephoneNumber = '123456'

    then:
    s.save()
    s.telephoneNumber == '123456'
  }

  def 'ensure subject stores challenge responses'() {
    setup:
    def s = ManagedSubject.build()
    def cr = ChallengeResponse.build()

    expect:
    s.save()

    when:
    s.addToChallengeResponse(cr)

    then:
    s.save()
    s.challengeResponse.size() == 1
    s.challengeResponse[0].subject == s
  }

  def 'ensure subject stores multiple challenge responses'() {
    setup:
    def s = ManagedSubject.build()
    def cr = ChallengeResponse.build()
    def cr2 = ChallengeResponse.build()
    def cr3 = ChallengeResponse.build()

    expect:
    s.save()

    when:
    s.addToChallengeResponse(cr)
    s.addToChallengeResponse(cr2)
    s.addToChallengeResponse(cr3)

    then:
    s.save()
    s.challengeResponse.size() == 3
    s.challengeResponse[2].subject == s
  }

  def 'ensure email must not be null or blank and be an email address'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.email = val
    def result = s.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == s.errors['email']

    where:
    val << [null, '', 'testuser', 'testuser@domain.com']
    reason << ['nullable', 'blank', 'email', '']
    expectedResult << [false, false, false, true]
  }

  def 'ensure cn must not be null or blank and either singular or first<space>last name formatted'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.cn = val
    def result = s.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == s.errors['cn']

    where:
    val << [null, '', 'Testuser', 'Test User', 'Mr Test User']
    reason << ['nullable', 'blank', '', '', 'cn']
    expectedResult << [false, false, true, true, false]
  }

  def 'ensure sharedtoken must not be null or blank'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.sharedToken = val
    def result = s.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == s.errors['sharedToken']

    where:
    val << [null, '', 'dfasf$@5asf#$',]
    reason << ['nullable', 'blank', '']
    expectedResult << [false, false, true]
  }

  def 'ensure shared token must be unique'() {
    setup:
    def s = ManagedSubject.build()
    def s2 = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()
    s2.validate()

    when:
    s.sharedToken = s2.sharedToken

    then:
    !s.save()
    'unique' == s.errors['sharedToken']
  }

  def 'ensure eduPersonEntitlement can be null not be blank'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.eduPersonEntitlement = val

    then:
    expected == s.validate()
    if(!expected)
     reason == s.errors['eduPersonEntitlement']

    where:
    val << [null, '', 'some:entitlement:val;another:entitlement:val']
    reason << ['', 'blank', '']
    expected << [true, false, true]
  }

  def 'ensure mobileNumber can be null not be blank'() {
    setup:
    def s = ManagedSubject.build()
    mockForConstraintsTests(ManagedSubject, [s])

    expect:
    s.validate()

    when:
    s.mobileNumber = val

    then:
    expected == s.validate()
    if(!expected)
     reason == s.errors['mobileNumber']

    where:
    val << [null, '', '0411222333']
    reason << ['', 'blank', '']
    expected << [true, false, true]
  }

  def 'ensure active is false by default'() {
    when:
    def s = ManagedSubject.build()

    then:
    !s.active
  }

  def 'ensure functioning when active, not locked and sponsored'() {
    setup:
    def s = ManagedSubject.build(active:true, locked:false)

    when:
    s.organization = Organization.build(active:true)
    s.group = Group.build(organization:s.organization, active:true)

    then:
    s.functioning()
  }

  def 'ensure not functioning when active and sponsor org is not functioning'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.organization = Organization.build(active:false)
    s.group = Group.build(organization:s.organization, active:true)

    then:
    !s.functioning()
  }

  def 'ensure not functioning when active and sponsor group is not functioning'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.organization = Organization.build(active:true)
    s.group = Group.build(organization:s.organization, active:false)

    then:
    !s.functioning()
  }

  def 'ensure not functioning when inactive and sponsored'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.active = false
    s.organization = Organization.build()
    s.group = Group.build(organization:s.organization)

    then:
    !s.functioning()
  }

  def 'ensure not functioning when active and sponsored but locked by AAF'() {
    setup:
    def s = ManagedSubject.build(active:true, locked:true)

    when:
    s.active = false
    s.organization = Organization.build()
    s.group = Group.build(organization:s.organization)

    then:
    !s.functioning()
  }

  def 'ensure apiKey is always created'() {
    when:
    def s = ManagedSubject.build()

    then:
    s.validate()
    s.apiKey != null
    s.apiKey.size() == 16
  }

  def 'ensure eptidKey is always created'() {
    when:
    def s = ManagedSubject.build()

    then:
    s.validate()
    s.eptidKey != null
    s.eptidKey.size() == 12
  }

  def 'ensure resetCode is sanitized'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.resetCode = 'abcIlO0'

    then:
    s.resetCode == 'abciLo9'
  }

  def 'ensure resetCodeExternal is sanitized'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.resetCodeExternal = 'abcIlO0'

    then:
    s.resetCodeExternal == 'abciLo9'
  }

  def 'ensure resetCode cannot equal resetCodeExternal'() {
    setup:
    def s = ManagedSubject.build()

    when:
    s.resetCode = '123456'
    s.resetCodeExternal = '123456'

    then:
    !s.validate()
  }

  def 'ensure accounts are correctly locked'() {
    setup:
    def s = ManagedSubject.build()

    expect:
    s.stateChanges == null
    !s.locked

    when:
    s.lock("reason", "category", "environment", null)

    then:
    s.locked
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.LOCKED
  }

  def 'ensure accounts are correctly unlocked'() {
    setup:
    def s = ManagedSubject.build(failedResets:2)
    s.lock("reason", "category", "environment", null)

    expect:
    s.locked
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.LOCKED

    when:
    s.unlock("reason2", "category2", "environment2", null)

    then:
    !s.locked
    s.failedResets == 0
    s.stateChanges.toArray()[1].event == StateChangeType.UNLOCKED
  }

  def 'ensure accounts are correctly blocked'() {
    setup:
    def s = ManagedSubject.build()

    expect:
    s.stateChanges == null
    !s.blocked

    when:
    s.block("reason", "category", "environment", null)

    then:
    s.blocked
    !s.functioning()
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.BLOCKED
  }

  def 'ensure accounts are correctly unblocked'() {
    setup:
    def s = ManagedSubject.build(failedResets:2, active:true)
    s.organization.active = true
    s.block("reason", "category", "environment", null)

    expect:
    s.blocked
    !s.functioning()
    s.stateChanges.toArray()[0].event == StateChangeType.BLOCKED

    when:
    s.unblock("reason2", "category2", "environment2", null)

    then:
    !s.blocked
    s.functioning()
    s.failedResets == 0
    s.stateChanges.toArray()[1].event == StateChangeType.UNBLOCKED
  }

  def 'ensure accounts are correctly deactivated'() {
    setup:
    def s = ManagedSubject.build(active:true)

    expect:
    s.stateChanges == null
    s.active

    when:
    s.deactivate("reason", "category", "environment", null)

    then:
    !s.active
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.DEACTIVATE
  }

  def 'ensure accounts are correctly activated'() {
    setup:
    def s = ManagedSubject.build(failedLogins:2)
    s.deactivate("reason", "category", "environment", null)

    expect:
    !s.active
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.DEACTIVATE

    when:
    s.activate("reason2", "category2", "environment2", null)

    then:
    s.active
    s.failedLogins == 0
    s.stateChanges.toArray()[1].event == StateChangeType.ACTIVATE
  }

  def 'ensure accounts are correctly incremented when failed password reset occurs'() {
    setup:
    def s = ManagedSubject.build(active:true)

    expect:
    s.failedResets == 0
    s.active

    when:
    s.increaseFailedResets()

    then:
    s.failedResets == 1
    s.active
  }

  def 'ensure accounts are correctly archived'() {
    setup:
    def s = ManagedSubject.build()

    expect:
    s.stateChanges == null
    !s.archived

    when:
    s.archive("reason", "category", "environment", null)

    then:
    s.archived
    !s.functioning()
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.ARCHIVED
  }

  def 'ensure accounts are correctly unarchived'() {
    setup:
    def s = ManagedSubject.build(active:true)
    s.organization.active = true
    s.archive("reason", "category", "environment", null)

    expect:
    s.archived
    !s.functioning()
    s.stateChanges.size() == 1
    s.stateChanges.toArray()[0].event == StateChangeType.ARCHIVED

    when:
    s.unarchive("reason2", "category2", "environment2", null)

    then:
    !s.archived
    s.functioning()
    s.stateChanges.toArray()[1].event == StateChangeType.UNARCHIVED
  }

  def 'Ensure super administrator can always create ManagedSubject'() {
    setup:
    def g = Group.build()
    def ms = ManagedSubject.build(group:g)
    g.blocked = true
    shiroSubject.isPermitted("app:administrator") >> true

    when:
    def result = ms.canCreate(g)

    then:
    result
  }

  def 'Ensure non administrator cant create ManagedSubject'() {
    setup:
    def g = Group.build()
    def ms = ManagedSubject.build(group:g)

    when:
    def result = ms.canCreate(g)

    then:
    !result
  }

  def 'Ensure administrator can create ManagedSubject'() {
    setup:
    def g = Group.build()
    def ms = ManagedSubject.build(organization:g.organization, group:g)
    g.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${g.organization.id}:group:${g.id}:managedsubject:create") >> true

    when:
    def result = ms.canCreate(g)

    then:
    result
  }

  def 'Ensure administrator cant create ManagedSubject if owner is not functioning'() {
    setup:
    def g = Group.build()
    g.blocked = true
    def ms = ManagedSubject.build(group:g)
    shiroSubject.isPermitted("app:manage:organization:${g.organization.id}:group:${g.id}:managedsubject:create") >> true

    when:
    def result = ms.canCreate(g)

    then:
    !result
  }

  def 'Ensure non administrator cant modify ManagedSubject'() {
    setup:
    def ms = ManagedSubject.build()

    when:
    def result = ms.canMutate()

    then:
    !result
  }

  def 'Ensure super administrator can always modify ManagedSubject'() {
    setup:
    def ms = ManagedSubject.build(archived:true, blocked:true)
    shiroSubject.isPermitted("app:administrator") >> true

    when:
    def result = ms.canMutate()

    then:
    result
  }

  def 'Ensure administrator cant modify ManagedSubject when blocked'() {
    setup:
    def ms = ManagedSubject.build(archived:false, blocked:true)
    ms.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${ms.organization.id}:group:${ms.group.id}:managedsubject:${ms.id}:edit") >> true

    when:
    def result = ms.canMutate()

    then:
    !result
  }

  def 'Ensure administrator cant modify ManagedSubject when archived'() {
    setup:
    def ms = ManagedSubject.build(archived:true, blocked:false)
    ms.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${ms.organization.id}:group:${ms.group.id}:managedsubject:${ms.id}:edit") >> true

    when:
    def result = ms.canMutate()

    then:
    !result
  }

  def 'Ensure administrator cant modify ManagedSubject when owner cant be modified'() {
    setup:
    def ms = ManagedSubject.build(archived:false, blocked:false)
    ms.organization.active = true
    ms.group.blocked = true
    shiroSubject.isPermitted("app:manage:organization:${ms.organization.id}:group:${ms.group.id}:managedsubject:${ms.id}:edit") >> true

    when:
    def result = ms.canMutate()

    then:
    !result
  }

  def 'Ensure administrator can modify ManagedSubject when not blocked or archived'() {
    setup:
    def ms = ManagedSubject.build(archived:false, blocked:false)
    ms.organization.active = true
    shiroSubject.isPermitted("app:manage:organization:${ms.organization.id}:group:${ms.group.id}:managedsubject:${ms.id}:edit") >> true

    when:
    def result = ms.canMutate()

    then:
    result
  }

  def 'Ensure super administrator can always delete ManagedSubject'() {
    setup:
    def ms = ManagedSubject.build()
    ms.group.blocked = true
    shiroSubject.isPermitted("app:administrator") >> true

    when:
    def result = ms.canDelete()

    then:
    result
  }

  def 'Ensure non super administrator cant delete ManagedSubject'() {
    setup:
    def ms = ManagedSubject.build()

    when:
    def result = ms.canDelete()

    then:
    !result
  }

  def 'Ensure account with null expiry returns false for isExpired'() {
    setup:
    def ms = ManagedSubject.build()

    when:
    def result = ms.isExpired()

    then:
    !result
  }

  def 'Ensure expired account returns true for isExpired'() {
    setup:
    def ms = ManagedSubject.build()
    def now = new Date()
    ms.accountExpires = now - 1

    when:
    def result = ms.isExpired()

    then:
    result
  }

  def 'Ensure not yet expired account returns false for isExpired'() {
    setup:
    def ms = ManagedSubject.build()
    def now = new Date()
    ms.accountExpires = now + 1

    when:
    def result = ms.isExpired()

    then:
    !result
  }

  def 'ensure canLogin fails if not password set'() {
    setup:
    def ms = ManagedSubject.build(hash: null)
    ms.organization.active = true

    when:
    ms.active = act

    then:
    ms.canLogin() == login

    where:
    act << [false, true]
    login << [false, false]
  }

  def 'ensure canLogin operates as expected'() {
    setup:
    def ms = ManagedSubject.build(hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    ms.organization.active = true

    when:
    ms.active = act

    then:
    ms.canLogin() == login

    where:
    act << [false, true]
    login << [false, true]
  }

  def 'ensure requiresLoginCaptcha operates as expected'() {
    setup:
    def ms = ManagedSubject.build()
    ms.organization.active = true

    when:
    ms.failedLogins = fails

    then:
    ms.requiresLoginCaptcha() == requires

    where:
    fails << [0,1,3,10]
    requires << [false, false, true, true]
  }

  def 'ensure failCaptcha behaves correctly'() {
    setup:
    def s = ManagedSubject.build(failedLogins:1, active:true, hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    s.organization.active = true

    expect:
    s.active
    s.canLogin()

    when:
    s.failCaptcha("reason", "category", "environment", null)

    then:
    s.active
    s.failedLogins == 1
    s.stateChanges.toArray()[0].event == StateChangeType.FAILCAPTCHA
  }

  def 'ensure failLogin increments correctly'() {
    setup:
    def s = ManagedSubject.build(failedLogins:2, active:true, hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    s.organization.active = true

    expect:
    s.active
    s.canLogin()
    !s.requiresLoginCaptcha()

    when:
    s.failLogin("reason", "category", "environment", null)

    then:
    s.active
    s.failedLogins == 3
    s.requiresLoginCaptcha()
    s.stateChanges.toArray()[0].event == StateChangeType.FAILLOGIN
  }

  def 'ensure failLogin deactivates after 5 failures'() {
    setup:
    def s = ManagedSubject.build(failedLogins:4, active:true, hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    s.organization.active = true

    expect:
    s.active
    s.canLogin()
    s.requiresLoginCaptcha()

    when:
    s.failLogin("reason", "category", "environment", null)

    then:
    !s.active
    s.failedLogins == 5
    s.requiresLoginCaptcha()
    s.stateChanges.toArray()[0].event == StateChangeType.FAILMULTIPLELOGIN
  }

  def 'ensure successfulLogin performs correctly'() {
    setup:
    def s = ManagedSubject.build(failedLogins:1, active:true, hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    s.organization.active = true

    expect:
    s.active
    s.canLogin()
    !s.requiresLoginCaptcha()

    when:
    s.successfulLogin("reason", "category", "environment", null)

    then:
    s.active
    s.failedLogins == 0
    !s.requiresLoginCaptcha()
    s.stateChanges.toArray()[0].event == StateChangeType.LOGIN
  }

  def 'ensure successfulLostPassword performs correctly'() {
    setup:
    def s = ManagedSubject.build(failedResets: 2, failedLogins:1, resetCode:'123', resetCodeExternal:'456', active:false, hash:'z0tYfrdu6V8stLN/hIu+xK8Rd5dsSueYwJ88XRgL2U4Z0JFSVspxsGOPK222')
    s.organization.active = true

    expect:
    !s.active
    !s.canLogin()

    when:
    s.successfulLostPassword()

    then:
    s.active
    s.canLogin()
    s.failedResets == 0
    s.failedLogins == 0
    !s.resetCode
    !s.resetCodeExternal
  }

}

package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

@TestFor(aaf.vhr.StateChange)
@Build([ManagedSubject, aaf.base.identity.Subject])
@Mock([StateChange, ManagedSubject, aaf.base.identity.Subject, Organization, Group])
class StateChangeSpec extends spock.lang.Specification {

  def 'ensure creation of basic state active change'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build()
    def change = new StateChange(event: StateChangeType.DEACTIVATE, reason:'system deactivated account')

    when:
    managedSubjectTestInstance.addToStateChanges(change)
    managedSubjectTestInstance.save()

    then:
    StateChange.count() == 1
    change.subject == managedSubjectTestInstance
    change.actionedBy == null
    managedSubjectTestInstance.stateChanges.size() == 1
  }

  def 'ensure creation of basic state locked change'() {
    setup:
    def managedSubjectTestInstance = ManagedSubject.build()
    def change = new StateChange(event: StateChangeType.LOCKED, reason:'system locked account')

    when:
    managedSubjectTestInstance.addToStateChanges(change)
    managedSubjectTestInstance.save()

    then:
    StateChange.count() == 1
    change.subject == managedSubjectTestInstance
    change.actionedBy == null
    managedSubjectTestInstance.stateChanges.size() == 1
  }

  def 'ensure creation of basic state active change by administrator'() {
    setup:
    def administrator = aaf.base.identity.Subject.build()
    def managedSubjectTestInstance = ManagedSubject.build()
    def change = new StateChange(event: StateChangeType.DEACTIVATE, reason:'admin deactivated account', actionedBy:administrator)

    when:
    managedSubjectTestInstance.addToStateChanges(change)
    managedSubjectTestInstance.save()

    then:
    StateChange.count() == 1
    change.subject == managedSubjectTestInstance
    managedSubjectTestInstance.stateChanges.size() == 1
    managedSubjectTestInstance.stateChanges.toArray()[0].actionedBy == administrator
  }

  def 'ensure creation of basic state locked change by administrator'() {
    setup:
    def administrator = aaf.base.identity.Subject.build()
    def managedSubjectTestInstance = ManagedSubject.build()
    def change = new StateChange(event: StateChangeType.LOCKED, reason:'admin locked account', actionedBy:administrator)

    when:
    managedSubjectTestInstance.addToStateChanges(change)
    managedSubjectTestInstance.save()

    then:
    StateChange.count() == 1
    change.subject == managedSubjectTestInstance
    managedSubjectTestInstance.stateChanges.size() == 1
    managedSubjectTestInstance.stateChanges.toArray()[0].actionedBy == administrator
  }

  def 'ensure creation of extended state active change by administrator'() {
    setup:
    def administrator = aaf.base.identity.Subject.build()
    def managedSubjectTestInstance = ManagedSubject.build()
    def change = new StateChange(event: StateChangeType.DEACTIVATE, reason:'admin deactivated account', actionedBy:administrator)
    change.category = 'failed_lost_password'
    change.environment = """IP: 1.2.3.4
    Hostname: CPE-121-222-.lnse2.woo.bigpond.com
    Browser: Google Chrome 24.0"""

    when:
    managedSubjectTestInstance.addToStateChanges(change)
    managedSubjectTestInstance.save()

    then:
    StateChange.count() == 1
    change.subject == managedSubjectTestInstance
    managedSubjectTestInstance.stateChanges.size() == 1
    managedSubjectTestInstance.stateChanges.toArray()[0].actionedBy == administrator
    change.environment.contains ("woo.bigpond")
  }

}

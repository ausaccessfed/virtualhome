package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

@TestFor(aaf.vhr.ManagedSubjectInvitation)
@Build([ManagedSubject, ManagedSubjectInvitation])
@Mock([Organization, Group])
class ManagedSubjectInvitationSpec extends UnitSpec {

  def "ensure new invitation is populated with code and has not been used"() {
    when:
    def inv = new ManagedSubjectInvitation()

    then:
    !inv.utilized
    inv.inviteCode != null
    inv.inviteCode.size() == 24
  }

  def "ensure new invitations are populated with unique codes"() {
    setup:
    def subject = ManagedSubject.build()
    def valid = true

    when:
    (1..1000).each {
      def inv = new ManagedSubjectInvitation(managedSubject:subject)
      mockForConstraintsTests(ManagedSubjectInvitation, [inv])

      def result = inv.validate()
      if(!result) {
        println inv.errors
        valid = false
      }
    }

    then:
    valid
  }

  def "ensure inviteCode constraints"() {    
    setup:
    def subject = ManagedSubject.build()
    def inv = new ManagedSubjectInvitation(managedSubject:subject)
    mockForConstraintsTests(ManagedSubjectInvitation, [inv])

    when:
    inv.inviteCode = code
    def result = inv.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == inv.errors['inviteCode']

    where:
    code | reason | expectedResult
    null | 'null' | false
  }

  def "ensure managedSubject constraints"() {    
    setup:
    def inv = new ManagedSubjectInvitation()
    mockForConstraintsTests(ManagedSubjectInvitation, [inv])

    when:
    inv.managedSubject = managedSubject
    def result = inv.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == inv.errors['managedSubject']

    where:
    managedSubject | reason | expectedResult
    null | 'null' | false
  }


}

package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

@TestFor(aaf.vhr.ChallengeResponse)
@Build([ManagedSubject, ChallengeResponse])
@Mock([Organization, Group, ManagedSubject])
class ChallengeResponseSpec extends UnitSpec {

  def 'ensure challenge must not be null or blank and be at least 6 characters long'() {
    setup:
    def cr = ChallengeResponse.build()
    mockForConstraintsTests(ChallengeResponse, [cr])

    expect:
    cr.validate()

    when:
    cr.challenge = val
    def result = cr.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == cr.errors['challenge']

    where:
    val << [null, '', '12345', '123456']
    reason << ['nullable', 'blank', 'minSize', '']
    expectedResult << [false, false, false, true]
  }

  def 'ensure hash must not be null or blank and be at least 6 characters long'() {
    setup:
    def cr = ChallengeResponse.build()
    mockForConstraintsTests(ChallengeResponse, [cr])

    expect:
    cr.validate()

    when:
    cr.hash = val
    def result = cr.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == cr.errors['hash']

    where:
    val << [null, '', 
    '0e819f575d8ca7e9b12dec270db4208c0ae20746d647432b2f846aff7ffc559c1029b85b23b7d25fa42a4d39aa3f76f6f9199310472ab1cb28921e', 
    '0e819f575d8ca7e9b12dec270db4208c0ae20746d647432b2f846aff7ffc559c1029b85b23b7d25fa42a4d39aa3f76f6f9199310472ab1cb28921e3e5347db47', 
    '0e819f575d8ca7e9b12dec270db4208c0ae20746d647432b2f846aff7ffc559c1029b85b23b7d25fa42a4d39aa3f76f6f9199310472ab1cb28921e3e5347db477']
    reason << ['nullable', 'blank', 'minSize', '', 'maxSize']
    expectedResult << [false, false, false, true, false]
  }

  def 'ensure salt must not be null or blank and exactly 29 characters long'() {
    setup:
    def cr = ChallengeResponse.build()
    cr.hash = '0e819f575d8ca7e9b12dec270db4208c0ae20746d647432b2f846aff7ffc559c1029b85b23b7d25fa42a4d39aa3f76f6f9199310472ab1cb28921e3e5347db47'
    mockForConstraintsTests(ChallengeResponse, [cr])

    expect:
    cr.validate()

    when:
    cr.salt = val
    def result = cr.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == cr.errors['salt']

    where:
    val << [null, '', 
    '$2a$12$zJCuKWn8srzSFqCH8P', 
    '$2a$12$zJCuKWn8srzSFqCH8P/bAu',
    '$2a$12$zJCuKWn8srzSFqCH8P/bAu1']
    reason << ['nullable', 'blank', 'minSize', '', '']
    expectedResult << [false, false, false, true, false]
  }

}

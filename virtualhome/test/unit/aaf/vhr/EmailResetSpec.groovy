package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

@TestFor(aaf.vhr.EmailReset)
@Build([ManagedSubject, EmailReset])
@Mock([Organization, Group, ManagedSubject])
class EmailResetSpec extends UnitSpec {

  def 'ensure code must not be null or blank and 24 characters long'() {
    setup:
    def er = EmailReset.build()
    mockForConstraintsTests(EmailReset, [er])

    expect:
    er.validate()

    when:
    er.code = val
    def result = er.validate() 

    then:
    result == expectedResult

    if (!expectedResult)
      reason == er.errors['code']

    where:
    val << [null, '',
            org.apache.commons.lang.RandomStringUtils.randomAlphanumeric(23),
            org.apache.commons.lang.RandomStringUtils.randomAlphanumeric(24),
            org.apache.commons.lang.RandomStringUtils.randomAlphanumeric(25)]
    expectedResult << [false,false,false,true,false]
    reason << ['nullable', 'blank', 'minSize', '', 'maxSize']
  }

  def 'ensure hash must not be null or blank and be at least 6 characters long'() {
    setup:
    def er = EmailReset.build()
    mockForConstraintsTests(EmailReset, [er])

    expect:
    er.validate()

    when:
    er.hash = val
    def result = er.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == er.errors['hash']

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
    def er = EmailReset.build()
    mockForConstraintsTests(EmailReset, [er])

    expect:
    er.validate()

    when:
    er.salt = val
    def result = er.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == er.errors['salt']

    where:
    val << [null, '', 
    '$2a$12$zJCuKWn8srzSFqCH8P', 
    '$2a$12$zJCuKWn8srzSFqCH8P/bAu',
    '$2a$12$zJCuKWn8srzSFqCH8P/bAu1']
    reason << ['nullable', 'blank', 'minSize', '', '']
    expectedResult << [false, false, false, true, false]
  }

  def 'ensure validUntil must not be null and a valid date'() {
    setup:
    def er = EmailReset.build()
    mockForConstraintsTests(EmailReset, [er])

    expect:
    er.validate()
    
    when:
    er.validUntil = val
    def result = er.validate()

    then:
    result == expectedResult

    if (!expectedResult)
      reason == er.errors['validUntil']

    where:
    val << [null, new Date()] 
    reason << ['nullable', '']
    expectedResult << [false, true]
  }
}

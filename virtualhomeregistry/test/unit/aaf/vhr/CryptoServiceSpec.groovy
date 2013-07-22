package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject
import aaf.vhr.crypto.BCrypt

@TestFor(aaf.vhr.CryptoService)
@Build([ManagedSubject, ChallengeResponse, EmailReset])
@Mock([Organization, Group, ManagedSubject])
class CryptoServiceSpec extends UnitSpec {

  def cs

  def setup() {
    cs = new CryptoService(grailsApplication: grailsApplication)
    grailsApplication.config.aaf.vhr.crypto.log_rounds = 4
    grailsApplication.config.aaf.vhr.crypto.sha_rounds = 2048
  }

  def 'validate various passwords store and confirm correctly'() {
    setup:
    def subject = ManagedSubject.build()
    subject.hash = null
    subject.plainPassword = pw
    subject.plainPasswordConfirmation = pw

    expect:
    subject.hash == null

    when:
    cs.generatePasswordHash(subject)

    then:
    subject.hash.size() == 60
    subject.validate()
    cs.verifyPasswordHash(pw, subject)

    where:
    pw << ['today123', 'I really enjoy XKCD.com 936 style PasswordS', 'XXYfgLvCehJ6qjflkMRBZ99Jw2I=']
  }

  def 'validate various passwords fail if not entered correctly'() {
    setup:
    def subject = ManagedSubject.build()
    subject.hash = null
    subject.plainPassword = pw
    subject.plainPasswordConfirmation = pw

    expect:
    subject.hash == null

    when:
    cs.generatePasswordHash(subject)

    then:
    subject.hash.size() == 60
    subject.validate()
    !cs.verifyPasswordHash(plainPW, subject)

    where:
    pw << ['today123', 'I really enjoy XKCD.com 936 style PasswordS', 'XXYfgLvCehJ6qjflkMRBZ99Jw2I=']
    plainPW << ['yesterday123', 'I really enjoy XKCD.com 936 style Passwords', 'XXYfgLvCehJ6qjflkMRBZ99Jw2I==']
  }

  def 'validate passwords larger then 72 still validate correctly even though silently dropping extra char'() {
    setup:
    def subject = ManagedSubject.build()
    subject.hash = null
    subject.plainPassword = pw
    subject.plainPasswordConfirmation = pw

    expect:
    subject.hash == null

    when:
    cs.generatePasswordHash(subject)

    then:
    subject.hash.size() == 60
    subject.validate()
    cs.verifyPasswordHash(plainPW, subject) == expected

    where:
    pw << [ '1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D89o', 
            '1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D89o',
            '1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D89o']
    plainPW << ['1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D89o', 
                '1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D8',
                '1Tix4JWX8OdFgPrf0JBy/RQAE1SjMgkP/yjG6cDFV7fElPgQTe3vuL77w95qwcUvU+Nqh9D']
    expected << [true, true, false]
  }

  def 'Validate bCrypt salt is always 29 char regardless of log_rounds'() {
    when:
    def salt = BCrypt.gensalt(rounds)

    then:
    salt.size() == 29

    where:
    rounds << [2,6,10,14,18]
  }

  def 'Validate sha512 hash creation for ChallengeResponse'() {
    setup:
    def cr = new ChallengeResponse(challenge:challenge)
    cr.response = response

    expect:
    cr.hash == null
    cr.challenge == challenge
    cr.response == response

    when:
    cs.generateChallengeResponseHash(cr)
    cr.response = null
    def verify = cs.verifyChallengeResponseHash(response, cr)

    then:
    verify

    where:
    challenge << ["What was your mothers maiden name?",
                  "What is your favourite TV show?",
                  "What is the haxors name who wrote this test?"]
    response << ["My mother's maiden name was jones",
                 "Inspector Gadget! goGadgetgo",
                 "bradleY"]
  }

  def 'Validate code and sha512 hash creation for ChallengeResponse'() {
    setup:
    def er = EmailReset.build()

    when:
    cs.generateEmailResetHash(er)
    def verify = cs.verifyEmailResetHash(er.code, er)

    then:
    verify
    er.code.size() == 24
    er.hash.size() == 128
    er.salt.size() == 29

  }

}

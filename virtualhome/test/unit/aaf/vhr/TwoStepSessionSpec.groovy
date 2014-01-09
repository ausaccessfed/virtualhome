package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

import test.shared.ShiroEnvironment

@TestFor(aaf.vhr.ManagedSubject)
@Build([ManagedSubject, Organization, Group])
@Mock([ManagedSubject, Organization, Group])
class TwoStepSessionSpec extends spock.lang.Specification  {

  def 'populate setups up initial session state'() {
    setup:
    def c = new TwoStepSession()

    when:
    c.populate()

    then:
    c.expiry != null
    c.value != null
    c.value.length() == 64
  }

}

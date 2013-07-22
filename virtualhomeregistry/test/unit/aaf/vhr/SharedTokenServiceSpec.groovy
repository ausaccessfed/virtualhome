package aaf.vhr

import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.vhr.ManagedSubject

@TestFor(aaf.vhr.SharedTokenService)
@Build([ManagedSubject])
@Mock([Organization, Group])
class SharedTokenServiceSpec extends UnitSpec {
  
  def st

  def setup() {
    st = new SharedTokenService(grailsApplication: grailsApplication)
    grailsApplication.config.aaf.vhr.sharedtoken.idp_entityid="https://test.server.com/idp"
    grailsApplication.config.aaf.vhr.sharedtoken.sha_rounds=2048
  }

  def 'ensure formatter replaces + with -'() {
    setup:
    String input = "CVDl+Wfilmxp9OhCWI+XKZb40Uw"

    when:
    def aepst = st.format(input)

    then:
    aepst == "CVDl-Wfilmxp9OhCWI-XKZb40Uw"
  }

  def 'ensure formatter replaces / with _'() {
    setup:
    String input = "CVDl/Wfilm//9OhCWI/XKZb40Uw"

    when:
    def aepst = st.format(input)

    then:
    aepst == "CVDl_Wfilm__9OhCWI_XKZb40Uw"
  }

  def 'ensure formatter removes all padding = characters'() {
    when:
    def aepst = st.format(val)

    then:
    aepst == expected

    where:
    val << ['Wfilmxp9OhCWI=', 'Wfilmxp9OhCWI==','Wfilmxp9OhCWI']
    expected << ['Wfilmxp9OhCWI', 'Wfilmxp9OhCWI', 'Wfilmxp9OhCWI']
  }

  def 'ensure formatter handles all cases in the same input'() {
    setup:
    String input = "C/Dl+Wfilmxp9OhCWI+XKZb/0Uw=="

    when:
    def aepst = st.format(input)

    then:
    aepst == "C_Dl-Wfilmxp9OhCWI-XKZb_0Uw"
  }

  def 'create basic SHA1 shared token'() {
    setup:
    def tokens = []
    def subject = ManagedSubject.build()

    when:
    st.generate(subject)

    then:
    def token = subject.sharedToken
    token.length() == 27
    !token.contains('/')
    !token.contains('+')
    !token.contains('=')
  }
}

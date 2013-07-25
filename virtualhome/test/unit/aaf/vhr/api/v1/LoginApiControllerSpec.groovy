package aaf.vhr.api.v1

import grails.test.mixin.*
import grails.plugin.spock.*
import grails.buildtestdata.mixin.Build

import spock.lang.*

import aaf.base.identity.*

@TestFor(aaf.vhr.api.v1.LoginApiController)

class LoginApiControllerSpec extends spock.lang.Specification {

  def "recieve 410 is there is no such session"() {
    setup:
    def loginService = Mock(aaf.vhr.LoginService)
    controller.loginService = loginService

    params.sessionID = "1234abcd"

    when:
    controller.confirmsession()

    then:
    1 * loginService.sessionRemoteUser(params.sessionID) >> null
    response.status == 410
  }

  def "recieve valid json when session is present"() {
    setup:
    def loginService = Mock(aaf.vhr.LoginService)
    controller.loginService = loginService

    params.sessionID = "1234abcd"

    when:
    controller.confirmsession()

    then:
    1 * loginService.sessionRemoteUser(params.sessionID) >> 'testuser'
    response.status == 200
    response.contentType == 'application/json;charset=UTF-8'
    response.text == '{"remote_user":"testuser"}'
  }

}

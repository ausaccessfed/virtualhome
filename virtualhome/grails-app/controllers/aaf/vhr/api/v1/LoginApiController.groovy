package aaf.vhr.api.v1

import org.springframework.dao.DataIntegrityViolationException
import org.apache.shiro.SecurityUtils

import aaf.base.identity.Role
import aaf.base.identity.Permission

import groovy.json.*

class LoginApiController extends aaf.base.api.ApiBaseController {
  def loginService

  def confirmsession() {
    def remoteUser = loginService.sessionRemoteUser(params.sessionID)

    if(remoteUser) {
      log.info "API session verification for ${params.sessionID} provided response with remote_user of $remoteUser"
      render(contentType: 'application/json') { ['remote_user':remoteUser] }
    } else {
      log.error "API session verification for ${params.sessionID} failed, providing error response"
      response.status = 410
      render(contentType: 'text/json') { ['error':'session could not be validated', 'internalerror':'login service session cache indicates no associated session for the supplied id'] }
    }
  }

}

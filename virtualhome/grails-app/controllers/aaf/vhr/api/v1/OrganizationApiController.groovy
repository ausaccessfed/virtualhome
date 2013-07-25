package aaf.vhr.api.v1

import aaf.vhr.*

class OrganizationApiController extends aaf.base.api.ApiBaseController {
  def beforeInterceptor = [action: this.&validateRequest, except:['update']]

  def organizationService

  def update() {
    organizationService.populate()

    log.info "Organization API populate executed"
    render(contentType: 'application/json') { ['result':'success', 'count':Organization.count()] }
  }

}

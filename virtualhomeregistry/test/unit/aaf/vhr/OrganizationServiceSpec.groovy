package aaf.vhr

import grails.converters.*
import grails.test.mixin.*
import grails.buildtestdata.mixin.Build
import spock.lang.*
import grails.plugin.spock.*

import aaf.base.workflow.Task
import aaf.base.workflow.ProcessInstance
import aaf.base.workflow.ProcessPriority
import aaf.base.workflow.WorkflowProcessService
import aaf.base.workflow.WorkflowTaskService

@TestFor(aaf.vhr.OrganizationService)
@Build([aaf.vhr.Organization, ProcessInstance])
class OrganizationServiceSpec extends UnitSpec {

  def os
  def wts
  def wps

  def setup() {
    wts = Mock(WorkflowTaskService)
    wps = new WorkflowProcessService(workflowTaskService:wts)

    os = new OrganizationService(grailsApplication: grailsApplication, workflowProcessService: wps)
    grailsApplication.config.aaf.vhr.federationregistry.server = "https://manager.test.aaf.edu.au"
    grailsApplication.config.aaf.vhr.federationregistry.api.organisations = "/federationregistry/api/v1/organizations"
  }

  def 'expect no Organization details being retireved is handled gracefully'() {
    setup:
    os.metaClass.queryOrganizations = { server, api ->
      null
    }

    expect:
    Organization.count() == 0

    when:
    os.populate()

    then:
    Organization.count() == 0
  }

  def 'expect all new Organisations to be created correctly except those not functioning'() {
    setup:
    def workflows = 0
    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")

      if(workflows == 27 || workflows == 56)
        json2.organization.functioning == false

      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = Mock(ProcessInstance)
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 0
    workflows == 0

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 93

    def o = Organization.findWhere(frID:11)
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect all new Organisations to be created correctly but no workflows when errors with workflow system'() {
    setup:
    def workflows = 0
    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")
      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        [false, null]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 0
    workflows == 0

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 0

    def o = Organization.findWhere(frID:11)
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect no new Organisations to be created when errors saving'() {
    setup:
    def workflows = 0
    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")
      json2.organization
    }

    Organization.metaClass.save = { null }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 0
    workflows == 0

    when:
    os.populate()

    then:
    Organization.count() == 0
  }

  def 'expect some existing Organisations to be updated and all new Organisations to be created correctly'() {
    setup:
    def workflows = 0

    new Organization(frID:11, name:"test", displayName:"test displayName", description:"test description").save()
    new Organization(frID:146, name:"test2", displayName:"test2 displayName", description:"test2 description").save()

    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")
      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 2
    Organization.first().displayName == "test displayName"
    Organization.first().frID == 11

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 91

    def o = Organization.findWhere(frID:11)
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect existing Organization that has been disabled in FR to be made inactive here'() {
    setup:
    def workflows = 0

    new Organization(frID:11, name:"test", displayName:"test displayName", description:"test description", active:true).save()
    new Organization(frID:146, name:"test2", displayName:"test2 displayName", description:"test2 description", active:true).save()

    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")

      if(json2.organization.id == 11 || json2.organization.id == 146) {
        json2.organization.functioning = false
      }

      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 2
    Organization.first().displayName == "test displayName"
    Organization.first().frID == 11
    Organization.first().active

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 91

    def o = Organization.findWhere(frID:11)
    !o.active
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    !o2.active
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect existing inactive Organization that has been re-activated in FR to be made active here'() {
    setup:
    def workflows = 0

    new Organization(frID:11, name:"test", displayName:"test displayName", description:"test description", active:false, undergoingWorkflow:false).save()
    new Organization(frID:146, name:"test2", displayName:"test2 displayName", description:"test2 description", active:false, undergoingWorkflow:false).save()

    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")

      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 2
    Organization.first().displayName == "test displayName"
    Organization.first().frID == 11
    !Organization.first().active
    Organization.last().frID == 146
    !Organization.last().active

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 91

    def o = Organization.findWhere(frID:11)
    o.active
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    o2.active
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect existing Organization undergoing workflow here is not made active regardless of being active in FR'() {
    setup:
    def workflows = 0

    new Organization(frID:11, name:"test", displayName:"test displayName", description:"test description", active:false, undergoingWorkflow:false).save()
    new Organization(frID:146, name:"test2", displayName:"test2 displayName", description:"test2 description", active:false, undergoingWorkflow:true).save()

    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")

      json2.organization
    }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> 
        workflows++
      }
    }

    expect:
    Organization.count() == 2
    Organization.first().displayName == "test displayName"
    Organization.first().frID == 11
    !Organization.first().active
    Organization.last().frID == 146
    !Organization.last().active

    when:
    os.populate()

    then:
    Organization.count() == 93
    workflows == 91

    def o = Organization.findWhere(frID:11)
    o.active
    o.name == "ramp.org.au"
    o.displayName == "ramp.org.au"
    o.description == "Boostrappted IdP of: ramp.org.au"

    def o2 = Organization.findWhere(frID:146)
    !o2.active
    o2.name == "usc.edu.au"
    o2.displayName == "University of the Sunshine Coast"
    o2.description == null
  }

  def 'expect no existing Organisations to be updated and no new Organisations to be created when errors saving'() {
    setup:
    def workflows = 0

    new Organization(frID:11, name:"test", displayName:"test displayName", description:"test description").save()
    new Organization(frID:146, name:"test2", displayName:"test2 displayName", description:"test2 description").save()

    def json = JSON.parse(new FileInputStream("test/data/organisations.json"), "UTF-8")

    os.metaClass.queryOrganizations = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api == grailsApplication.config.aaf.vhr.federationregistry.api.organisations

      json.organizations
    }

    os.metaClass.queryOrganization = { server, api ->
      assert server == grailsApplication.config.aaf.vhr.federationregistry.server
      assert api.startsWith('/federationregistry/api/v1/organizations/')

      def jsonFile = new File("test/data/orgJSON/${api.replace('/','-')}.json".replace('-federationregistry-api-v1-organizations', 'organization'))
      def json2 = JSON.parse(new FileInputStream(jsonFile), "UTF-8")
      json2.organization
    }

    Organization.metaClass.save = { null }

    wps.metaClass {
      initiate = { String processName, String instanceDescription, ProcessPriority priority, Map params ->
        def instance = [] as ProcessInstance
        [true, instance]
      }
      run = {ProcessInstance processInstance -> }
    }

    expect:
    workflows == 0

    Organization.count() == 2
    Organization.first().displayName == "test displayName"
    Organization.first().frID == 11

    when:
    os.populate()

    then:
    Organization.count() == 2
  }

}
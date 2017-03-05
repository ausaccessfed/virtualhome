import aaf.base.identity.*
import aaf.vhr.*

/*
  Configure basic AAF VH components for new install

  Bradley Beddoes
  April 2013
*/
  
// Shibboleth IdP API Account
  
// Suggested generation $> openssl rand -base64 16 | tr -d '=+/\r\n'
String principal = ''  

// Suggested generation $> openssl rand -base64 16 | tr -d '=+/\r\n'
// This must be kept a secret and known only to the API user
String apiKey = ''

// Mandatory description field
String description = 'Shibboleth IdP API Account'




// NO MORE CHANGES BELOW THIS POINT

def apiSubject = new ApiSubject(principal:principal, apiKey:apiKey, enabled:true, description: description)
if(!apiSubject.save()) {
  apiSubject.errors.each { println it }
  return false
}

def orgService = ctx.getBean('organizationService')
orgService.populate()

println "VH has been populated with ${Organization.count()} organizations from Federation Registry"

import org.apache.log4j.DailyRollingFileAppender

grails.app.context = '/'
grails.serverURL = 'https://vho.test.aaf.edu.au'
grails.mail.default.from = 'noreply@vho.test.aaf.edu.au'

/* DEVELOPMENT CONFIGURATION - DELETE BELOW BLOCK IF PRODUCTION
greenmail.disabled = false
grails {
  resources.debug = true
  gsp.enable.reload = true
  logging.jul.usebridge = true
  mail {
    port = com.icegreen.greenmail.util.ServerSetupTest.SMTP.port
  }
}
dataSource {
  pooled = true
  driverClassName = "com.mysql.jdbc.Driver"
  dialect = org.hibernate.dialect.MySQL5InnoDBDialect
  dbCreate = "update"
  loggingSql = false
  
  url = "jdbc:mysql://localhost/virtualhomeregistry?useUnicode=yes&characterEncoding=UTF-8"
  username = "vhr_webapp"
  password = "password"
}

recaptcha {
  enabled = false
  useSecureAPI = false
}
END DEVELOPMENT CONFIGURATION - DELETE ABOVE BLOCK IF PRODUCTION */

/* PRODUCTION/TEST CONFIGURATION - DELETE BELOW BLOCK IF DEVELOPMENT
greenmail.disabled = true
testDataConfig.enabled = false
grails {
  resources.debug = false  
  gsp.enable.reload = false
  logging.jul.usebridge = false
  mail {
    host = 'localhost' // More advanced mail config available per: http://grails.org/plugin/mail
  }
}

dataSource {
  dbCreate = "update"
  dialect= org.hibernate.dialect.MySQL5InnoDBDialect
  jndiName= "java:comp/env/jdbc/VHR" 
}

recaptcha {
  publicKey = ''
  privateKey = ''

  includeNoScript = true
  forceLanguageInURL = false

  enabled = true
  useSecureAPI = true
}
END PRODUCTION/TEST CONFIGURATION - DELETE ABOVE BLOCK IF DEVELOPMENT*/

aaf {
  vhr {
    federationregistry {
      server = "https://manager.test.aaf.edu.au"
      api {
        organisations = "/federationregistry/api/v1/organizations/"
      }
    }
    crypto {
      log_rounds = 6      // BCrypt rounds. Ensure higher in production and increased over time.
      sha_rounds = 1024
    }
    sharedtoken {
      sha_rounds = 1024
      idp_entityid = 'https://vho.test.aaf.edu.au/idp/shibboleth'   // VHR SP Entity ID
    }
    passwordreset {
      second_factor_required = false
      
      reset_code_length = 6
      reset_sms_text = "Your AAF Virtual Home 'SMS Code' to reset your lost password is: {0}"
      reset_attempt_limit = 5

      api_endpoint = 'https://rest.nexmo.com'
      api_key = ''
      api_secret = ''
    }
    login {
      ssl_only_cookie = true
      path = '/'
      validity_period_minutes = 2
      require_captcha_after_tries = 2
    }
  }
  base {
    //Session Expiry Warning - minutes
    session_warning = 50 
    session_decision_time = 5

    // Deployed AAF environment [development | test | production]
    deployment_environment = "test"

    administration {
      initial_administrator_auto_populate = true
    }

    realms {
      api {
        active = true
      }
      federated { 
        active = true
        automate_login = false
        auto_provision = true
        sso_endpoint = "/Shibboleth.sso/Login"

        // Supported as fallback for problematic webservers
        // AAF webserver configuration (ajp) shouldn't require this to be false.
        // See https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess for more
        request.attributes = true 
        
        mapping {
          principal = "persistent-id"   // The unique and persistent ID used to identify this principal for current and subsequent sessions (eduPersonTargetedID)
          credential = "Shib-Session-ID"  // The internal session key assigned to the session associated with the request and hence the credential used
          entityID = "Shib-Identity-Provider" // The entityID of the IdP that authenticated the subject associated with the request.
          
          applicationID = "Shib-Application-ID" // The applicationId property derived for the request.     
          idpAuthenticationInstant = "Shib-Authentication-Instant" // The ISO timestamp provided by the IdP indicating the time of authentication. 
          
          cn = "cn"
          email= "mail"
          sharedToken = "auEduPersonSharedToken"
        }

        development {
          active = false
        }
      }
    }
  }
}

// Logging
log4j = {
  appenders {
    appender new DailyRollingFileAppender(name:"app-security", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhomeregistry/application/logs/app-security.log", datePattern:"'.'yyyy-MM-dd")
    appender new DailyRollingFileAppender(name:"app", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhomeregistry/application/logs/app.log", datePattern:"'.'yyyy-MM-dd")
    appender new DailyRollingFileAppender(name:"app-grails", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhomeregistry/application/logs/app-grails.log", datePattern:"'.'yyyy-MM-dd")
    appender new DailyRollingFileAppender(name:"stacktrace", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhomeregistry/application/logs/app-stacktrace.log", datePattern:"'.'yyyy-MM-dd")
  }

  info  'app-security'  :['grails.app.filters'], additivity: false

  info  'app'           :['grails.app.controllers',
                          'grails.app.domains',
                          'grails.app.services',
                          'grails.app.realms',
                          'aaf.vhr',                       
                          'org.apache.shiro'], additivity: false
          
  warn  'app-grails'    :['org.codehaus.groovy.grails.web.servlet',
                          'org.codehaus.groovy.grails.web.pages',
                          'org.codehaus.groovy.grails.web.sitemesh',
                          'org.codehaus.groovy.grails.web.mapping.filter',
                          'org.codehaus.groovy.grails.web.mapping',
                          'org.codehaus.groovy.grails.commons',
                          'org.codehaus.groovy.grails.plugins'], additivity: false
}

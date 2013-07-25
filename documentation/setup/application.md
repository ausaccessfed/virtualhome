## Application Setup

Before proceeding be sure to have compiled the virtualhome-x.y.z.war file and copied it to your server.

**Console commands as ROOT**
1. Create the application directory structure

		mkdir /opt/virtualhome/application
		cd /opt/virtualhome/application
		mkdir config logs war
		chown tomcatweb.tomcatweb logs
		
1. Visit the Google recaptcha service and create a new account http://www.google.com/recaptcha and keys associated with your domain.
2. If you'd like to use SMS codes in your password reset process you'll need an account and credit with nexmo.com

1. Using the example configuration file application_config.groovy.orig that ships with the project create the application configuration file as `/opt/virtualhome/application/config/application_config.groovy` - each option within the file is reasonably self documenting.

    Here is an example of ours from the AAF test environment
    
            import org.apache.log4j.DailyRollingFileAppender

            grails.app.context = '/'
            grails.serverURL = 'https://vho.test.aaf.edu.au'
            grails.mail.default.from = 'noreply@vho.test.aaf.edu.au'

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
              publicKey = 'UNIQUE'
              privateKey = 'UNIQUE'

              includeNoScript = true
              forceLanguageInURL = false

              enabled = true
              useSecureAPI = true
            }

            aaf {
              vhr {
                federationregistry {
                  server = "https://manager.test.aaf.edu.au"
                  api {
                    organisations = "/federationregistry/api/v1/organizations/"
                  }
                }
                crypto {
                  log_rounds = 12
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
                  api_key = 'UNIQUE'
                  api_secret = 'UNIQUE'
                }
                login {
                  ssl_only_cookie = true
                  path = '/'
                  validity_period_minutes = 2
                  require_captcha_after_tries = 2
                }
              }
              base {
                // Bootstrap - Allows unauthenticated access to administrative console
                bootstrap = true

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
                    automate_login = true
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
                appender new DailyRollingFileAppender(name:"app-security", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhome/application/logs/app-security.log", datePattern:"'.'yyyy-MM-dd")
                appender new DailyRollingFileAppender(name:"app", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhome/application/logs/app.log", datePattern:"'.'yyyy-MM-dd")
                appender new DailyRollingFileAppender(name:"app-grails", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhome/application/logs/app-grails.log", datePattern:"'.'yyyy-MM-dd")
                appender new DailyRollingFileAppender(name:"stacktrace", layout:pattern(conversionPattern: "%d{[ dd.MM.yy HH:mm:ss.SSS]} %-5p %c %x - %m%n"), file:"/opt/virtualhome/application/logs/app-stacktrace.log", datePattern:"'.'yyyy-MM-dd")
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

1. Copy the virtualhome-x.y.z.war file to `/opt/virtualhome/application/war`
1. Set this war file as the currently utilised version with a symlink

			ln -s /opt/virtualhome/application/war/virtualhome-x.y.z.war /opt/virtualhome/application/war/current
			
1. Create a ROOT.xml descriptor for the VHR webapp as shown. You will require the credentials for vhr_webapp database user which was previously created.

			<Context docBase="/opt/virtualhome/application/war/current"
              privileged="true"
              antiResourceLocking="false"
              antiJARLocking="false"
              unpackWAR="true"
              swallowOutput="true"
              reloadable="true">

              <Resource name="jdbc/VHR"
                auth="Container"
                type="javax.sql.DataSource"
                driverClassName="com.mysql.jdbc.Driver"
                url="jdbc:mysql://localhost:3306/virtualhome?useUnicode=yes&amp;characterEncoding=UTF-8"
                username="vhr_webapp" 
                password="PASSWORD"
                maxActive="20" 
                maxIdle="10" 
                maxWait="10000" 
                validationQuery="/* ping */" 
                testOnBorrow="true" />

              <Environment name="config_dir" value="/opt/virtualhome/application/config" type="java.lang.String"/>

            </Context>

1. Move the ROOT.xml descriptor to /opt/virtualhome/tomcat/context and symlink to Tomcat conf/Catalina/localhost directory

		ln -s /opt/virtualhome/tomcat/context/ROOT.xml /opt/virtualhome/tomcat/apache-tomcat-7.x/conf/Catalina/localhost/ROOT.xml
		
1. Start your tomcat instance checking for any errors. You should be able to successfully navigate to https://vho.example.edu.au

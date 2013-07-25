## Shibboleth IdP Setup

Requires: Database Setup, General Web Server Setup, Tomcat Setup, Application Setup

Before proceeding be sure to download the latest Shibboleth IdP (2.3.8 at the time of writing) from www.shibboleth.net

**Console commands as ROOT**

1. If Tomcat is currently running stop it before proceeding
1. `mkdir /opt/virtualhome/shibboleth/shibboleth-src`
1. Extract latest shibboleth to /opt/virtualhome/shibboleth/shibboleth-src
1. Symlink /opt/virtualhome/shibboleth/shibboleth-src/current to latest release
	
		ln -s /opt/virtualhome/shibboleth/shibboleth-src/shibboleth-identityprovider-2.3.8 /opt/virtualhome/shibboleth/shibboleth-src/current

1. Set JAVA_HOME 

		export JAVA_HOME=/usr/lib/jvm/jre-1.7.0-openjdk.x86_64

1. Run install.sh in /opt/virtualhome/shibboleth/shibboleth-src/current
1. When prompted set shibboleth install directory to be /opt/virtualhome/shibboleth/shibboleth-idp
1. Copy the jars compiled and supplied by the VHR shibboleth-integration sub project to '/opt/virtualhome/shibboleth/shibboleth-src/current/lib/'

		json-simple-1.1.1.jar
		httpcore-4.2.2.jar
     	httpclient-4.2.2.jar
     	vhr-shibboleth.jar
         
1. Edit the file `/opt/virtualhome/shibboleth/shibboleth-src/current/src/main/webapp/WEB-INF/web.xml` to contain the following (you will require the **API token** and **secret** creted when deploying the VHR webapp in the configuration below):

       <filter>
        <filter-name>VhrFilter</filter-name>
        <filter-class>aaf.vhr.idp.http.VhrFilter</filter-class>
        <init-param>
          <param-name>loginEndpoint</param-name>
          <param-value><!-- https://VHR server address -->/login?ssourl=%s&amp;relyingparty=%s</param-value>
        </init-param>
        <init-param>
          <param-name>apiServer</param-name>
          <param-value><!-- https://VHR server address--></param-value>
        </init-param>
        <init-param>
          <param-name>apiEndpoint</param-name>
          <param-value>/api/v1/login/confirmsession/%s</param-value>
        </init-param>
        <init-param>
          <param-name>apiToken</param-name>
          <param-value><!-- API Subject --></param-value>
        </init-param>
        <init-param>
          <param-name>apiSecret</param-name>
          <param-value><!-- API Secret --></param-value>
        </init-param>
        <init-param>
          <param-name>requestingHost</param-name>
          <param-value><!-- VHR SERVER IP --></param-value>
        </init-param>
       </filter>
       <filter-mapping>
        <filter-name>VhrFilter</filter-name>
        <url-pattern>/Authn/RemoteUser</url-pattern>
       </filter-mapping>

   Here is an example of our test configuration:

       <filter>
          <filter-name>VhrFilter</filter-name>
          <filter-class>aaf.vhr.idp.http.VhrFilter</filter-class>
          <init-param>
            <param-name>loginEndpoint</param-name>
            <param-value>https://vho.test.aaf.edu.au/login?ssourl=%s&amp;relyingparty=%s</param-value>
          </init-param>
          <init-param>
            <param-name>apiServer</param-name>
            <param-value>https://vho.test.aaf.edu.au</param-value>
          </init-param>
          <init-param>
            <param-name>apiEndpoint</param-name>
            <param-value>/api/v1/login/confirmsession/%s</param-value>
          </init-param>
          <init-param>
            <param-name>apiToken</param-name>
            <param-value>IIyuXTT</param-value>
          </init-param>
          <init-param>
            <param-name>apiSecret</param-name>
            <param-value>Dn9BcZ9Y2Pb</param-value>
          </init-param>
          <init-param>
            <param-name>requestingHost</param-name>
            <param-value>192.168.1.1</param-value>
          </init-param>
          </filter>
       <filter-mapping>
         <filter-name>VhrFilter</filter-name>
         <url-pattern>/Authn/RemoteUser</url-pattern>
       </filter-mapping>

1. Continue IdP setup as normal for your federation. For the AAF that is undertaken by following the guidelines at http://wiki.aaf.edu.au/tech-info/identity-provider/idp-install-guide-2-3-8 - VHR uses the REMOTE USER authentication handler. Be sure to configure this and not username/password.

    For attribute resolution the VHR project supplies the specially created attribute-resolver.xml file within the configuration/idp directory. Be sure to use this as your attribute-resolver.xml **configuring baseScope and salt** to be unique to your installation. In addition the credentials for the database user vhr_idp created within the database documentation must be provided within the **ApplicationManagedConnection** element.

1. Create an idp.xml descriptor for the Shibboleth IdP web-app as shown. Again you will require the credentials for vhr_idp database user which was previously created.

		<Context docBase="/opt/virtualhome/shibboleth/shibboleth-idp/war/idp.war"
  			privileged="true"
  			antiResourceLocking="false"
  			antiJARLocking="false"
  			unpackWAR="false"
  			swallowOutput="true"
  			reloadable="true">

  			<Resource name="jdbc/VHR_IDP"
    			auth="Container"
    			type="javax.sql.DataSource"
    			driverClassName="com.mysql.jdbc.Driver"
    			url="jdbc:mysql://localhost:3306/virtualhome?useUnicode=yes&amp;characterEncoding=UTF-8"
    			username="vhr_idp" 
    			password="PASSWORD"
    			maxActive="20" 
    			maxIdle="10" 
    			maxWait="10000" 
    			validationQuery="/* ping */" 
    			testOnBorrow="true" />

		</Context>

1. Move the idp.xml descriptor to /opt/virtualhome/tomcat/context and symlink to Tomcat conf/Catalina/localhost directory

		ln -s /opt/virtualhome/tomcat/context/idp.xml /opt/virtualhome/tomcat/apache-tomcat-7.x/conf/Catalina/localhost/idp.xml

1. Start your Tomcat instance. Ensure the IdP web application deploys correctly. If you're having troubles getting the IdP started be sure increase your logging. VHR integration logging can be increased by adding the following to Shibboleth logging.xml configuration file

		<logger name="aaf.vhr.idp" level="DEBUG"/>

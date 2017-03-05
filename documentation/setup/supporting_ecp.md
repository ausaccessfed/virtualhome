## Shibboleth ECP Support

VH now supports ECP in an experimental/basic form.

It should be noted that accounts which have enabled 2-Step are **not required to enter a 2-Step code** when using ECP logins due to limitiations of the protocol and user experience.

*If you want to ensure 2-Step on all your accounts don't enable ECP.*

### Configuration

1. Edit the file `/opt/virtualhome/shibboleth/shibboleth-src/current/src/main/webapp/WEB-INF/web.xml` to contain the following (you will require the **API token** and **secret** creted when deploying the VHO webapp in the configuration below):

        <filter>
          <filter-name>VhrBasicAuthFilter</filter-name>
          <filter-class>aaf.vhr.idp.http.VhrBasicAuthFilter</filter-class>
          <init-param>
            <param-name>realm</param-name>
            <param-value><!-- VHO server displayName --></param-value>
          </init-param>
          <init-param>
            <param-name>apiServer</param-name>
            <param-value><!-- https://VHO server address--></param-value>
          </init-param>
          <init-param>
            <param-name>apiEndpoint</param-name>
            <param-value>/api/v1/login/basicauth</param-value>
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
            <param-value><!-- VHO SERVER IP --></param-value>
          </init-param>
        </filter>

        ...

        <filter-mapping>
          <filter-name>VhrBasicAuthFilter</filter-name>
          <url-pattern>/profile/SAML2/SOAP/ECP</url-pattern>
        </filter-mapping>

    Here is an example of our test configuration:

        <filter>
          <filter-name>VhrBasicAuthFilter</filter-name>
          <filter-class>aaf.vhr.idp.http.VhrBasicAuthFilter</filter-class>
          <init-param>
            <param-name>realm</param-name>
            <param-value>AAF Virtual Home (Test)</param-value>
          </init-param>
          <init-param>
            <param-name>apiServer</param-name>
            <param-value>https://vho.test.aaf.edu.au</param-value>
          </init-param>
          <init-param>
            <param-name>apiEndpoint</param-name>
            <param-value>/api/v1/login/basicauth</param-value>
          </init-param>
          <init-param>
            <param-name>apiToken</param-name>
            <param-value>redacted</param-value>
          </init-param>
          <init-param>
            <param-name>apiSecret</param-name>
            <param-value>redacted</param-value>
          </init-param>
          <init-param>
            <param-name>requestingHost</param-name>
            <param-value>10.10.0.2</param-value>
          </init-param>
        </filter>

        <filter-mapping>
          <filter-name>VhrBasicAuthFilter</filter-name>
          <url-pattern>/profile/SAML2/SOAP/ECP</url-pattern>
        </filter-mapping>

2. Restart your Tomcat instance and ECP should be functioning.

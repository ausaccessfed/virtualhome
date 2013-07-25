## Notes for AAF deployments

1. Ensure the Java trusts the AusCert CA

        keytool -import -trustcacerts -file /opt/virtualhome/pki/tls/certs/AUSCert_intermediate.crt -alias AUSCert -keystore $JAVA_HOME/lib/security/cacerts

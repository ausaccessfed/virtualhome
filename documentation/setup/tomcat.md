## Tomcat Setup

Before proceeding be sure to download the latest Apache Tomcat 7.x from http://tomcat.apache.org

**Console commands as ROOT**

1. Create the users `tomcat` and `tomcatweb`. Both should belong to the `tomcat` group.
1. Create the directory `/opt/virtualhome/tomcat` with ownership by root or high level system user and permissions 755.
1. Ensure the directory `/opt/virtualhome/tomcat/context` with ownership by tomcat.tomcat and permissions 750.
1. Copy the tomcat download to `/opt/virtualhome/tomcat`
1. Unpack

		tar xzvf apache-tomcat-7.x.tar.gz

1. Remove default web-apps

		rm -rf apache-tomcat-7.x/webapps/*

1. Set ownership to the tomcat user and common group

		chown -R tomcat.tomcat apache-tomcat-7.x;

1. Remove write permissions

		chmod -R go-w apache-tomcat-7.x

1. Allow the group to read config

		chmod 644 apache-tomcat-7.x/conf/*

1. Create the context files directory

    mkdir -p apache-tomcat-7.x/conf/Catalina/localhost
    chown -R tomcat.tomcat apache-tomcat-7.x/conf/Catalina

1. Allow write on required directories only

		cd apache-tomcat-7.x; sudo chown -R tomcatweb work/ temp/ logs/

1. Set the current symlink

		ln -s /opt/virtualhome/tomcat/apache-tomcat-7.x /opt/virtualhome/tomcat/current

1. Download the latest MySQL JDBC connector from the MySQL website
1. Copy mysql connector jar to `/opt/virtualhome/tomcat/current/lib`

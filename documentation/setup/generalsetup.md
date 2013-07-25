## General Web Server Setup

This document assumes a vanilla CentOS based web server for VHR.

The following installs Apache HTTPD 2 with SSL support and system wide OpenJDK 7.

**Console commands as ROOT**
  
    $> yum imstall httpd.x86_64
    $> yum install mod_ssl.x86_64
    $> yum install java-1.7.0-openjdk.x86_64
    $> mkdir /opt/virtualhome

1. Configure and harden your Apache VirtualServer. We recommend SSL for all VH instances. A base Virtual Host example is provided in configuration/apache/vho.conf

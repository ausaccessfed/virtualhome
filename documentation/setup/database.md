## Database Server Setup

This document assumes a vanilla CentOS based database server.

If using an existing database you will only need a subset of the instructions provided here. Check that environment closely resembles that suggested below especially for UTF-8 usage.

**Console commands as ROOT**

  $> yum install mysql mysql-server
  
  $> vi /etc/my.cnf

  	Add the following lines for '[mysqld]':

    innodb_file_per_table = true
    default_table_type = InnoDB
    collation_server=utf8_unicode_ci
    character_set_server=utf8

  $> chkconfig --level 2345 mysqld on; service mysqld start
  
  $> mysql -u root

**MySQL commands as root**

    mysql> drop database test;
    mysql> delete from mysql.user where not (host="localhost" and user="root");
    mysql> FLUSH PRIVILEGES;
    mysql> SET PASSWORD FOR 'root'@'localhost' = PASSWORD('SECURE PASSWORD');
    mysql> DELETE FROM mysql.user WHERE User = '';
    mysql> FLUSH PRIVILEGES;
    mysql> CREATE DATABASE virtualhome DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
    mysql> grant all privileges on virtualhome.* to 'vhr_webapp'@'localhost' identified by 'PASSWORD'
    mysql> grant all privileges on virtualhome.shibpid to 'vhr_idp'@'localhost' identified by 'PASSWORD2'
    mysql> grant select on virtualhome.* to 'vhr_idp'@'localhost' identified by 'PASSWORD2';
    mysql> use virtualhome;
    mysql> CREATE TABLE `shibpid` (
            `creationDate` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
            `deactivationDate` timestamp NULL default NULL,
            `localEntity` varchar(255) NOT NULL,
            `localId` varchar(255) NOT NULL,
            `peerEntity` varchar(255) NOT NULL,
            `peerProvidedId` varchar(255) default NULL,
            `persistentId` varchar(255) NOT NULL,
            `principalName` varchar(255) NOT NULL,
            KEY `localEntity_idx` (`localEntity`,`localId`,`peerEntity`),
            KEY `localEntity2_idx` (`deactivationDate`,`localEntity`,`localId`,`peerEntity`),
            KEY `persistentId2_idx` (`deactivationDate`,`persistentId`),
            KEY `persistentId_idx` (`persistentId`)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8;



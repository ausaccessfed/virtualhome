## Developing and building the VHR web application

### Pre-requisites
If you're new to this space you'll want to get a few things up and running before you can start development.

1. A *nix based development machine - I work directly on my Mac but a [Virtualbox VM](http://www.virtualbox.org) works just as well
1. An install of Java JDK. I am currently using a 7 release:
  
		java -version
		java version "1.7.0_07"
		Java(TM) SE Runtime Environment (build 1.7.0_07-b10)
		Java HotSpot(TM) 64-Bit Server VM (build 23.3-b01, mixed mode)
    
	You can find [offical Oracle JDK downloads here](http://www.oracle.com/technetwork/java/javase/downloads/index.html) or alternatively use an OpenJDK which works just as well.

1. Ensure you have a JAVA_HOME and appropriate JAVA_OPTS environment variables defined in your `~/.bash_profile`, here is an example of mine:

		export JAVA_HOME='/Library/Java/JavaVirtualMachines/jdk1.7.0_07.jdk/Contents/Home'
		export JAVA_OPTS='-Xms1024m -Xmx1024m -XX:MaxPermSize=256m'
  
	For Grails work the above memory allocations seem to give me the best performance.

1. [Install GVM](http://gvmtool.net/) using the below commands. You will require **bash, curl, zip and unzip** to be available on your system
  
    	curl -s get.gvmtool.net | bash
    	source "~/.gvm/bin/gvm-init.sh"
    	gvm install grails 2.2.0
    	gvm use grails 2.2.0

	Make sure Grails is correctly installed and referenced:

    	$> which grails
    	~/.gvm/grails/current/bin/grails

### Getting things up and running

1. You'll require the following repositories to be cloned from GitHub. I'd suggest making your own fork so you can maintain your own changes seperately.

		https://github.com/ausaccessfed/applicationbase
		https://github.com/ausaccessfed/virtualhome
		
1. Assuming you clone to `~/Development/repositories` This should give you a directory structure of:

		~/Development/repositories
								   |- applicationbase
								   |- virtualhome
								   
1.  As of VH 1.5.0 (March 2017) there is an extra step required to build the AAF
patched version of Groovy for dependency resolution purposes.

To build AAF Groovy:

    1. Be on Java 7
    1. Be in the root directory of the virtualhome project checked out from
    Github
    1. `git submodule init`
    1. cd aaf-patched-groovy
    1. ./gradlew clean dist

1. You can now develop as necessary in ../virtualhome

1. Build the war as follows

		cd ../virtualhome
		grails compile
		grails war
		
	**You can leave out the compile step in the future but I find it prevents resolution errors in downloading dependencies if you use it the first time you try to create the war file.**
	
### Customising branding, messages
# TODO

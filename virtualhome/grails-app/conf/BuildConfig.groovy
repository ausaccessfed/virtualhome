grails.servlet.version = "3.0"

grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"
grails.project.target.level = 1.7
grails.project.source.level = 1.7

grails.plugin.location.'aaf-application-base' = '../../applicationbase'
grails.plugin.location.'grails-sanitizer' = '../plugins/grails-sanitizer'

grails.project.dependency.resolution = {
  inherits("global") {
  }

  log "warn"
  checksums true
  
  repositories {
    inherits true

    grailsPlugins()
    grailsHome()
    grailsCentral()

    mavenLocal()
    mavenCentral()

    mavenRepo "http://repo.grails.org/grails/repo/"
    mavenRepo "http://download.java.net/maven/2/"
    mavenRepo "http://repository.jboss.com/maven2/"
  }

  dependencies {
    test 'mysql:mysql-connector-java:5.1.18'
    compile "com.google.guava:guava:14.0"
  }

  /*
    Types of plugin:
    build: Dependencies for the build system only
    compile: Dependencies for the compile step
    runtime: Dependencies needed at runtime but not for compilation (see above)
    test: Dependencies needed for testing but not at runtime (see above)
    provided: Dependencies needed at development time, but not during WAR deployment

    PLUGINS LISTED HERE SHOULD BE OVER AND ABOVE THOSE PROVIDED BY AAF-BASE-APPLICATION PLUGIN
  */
  plugins {
    compile ":csv:0.3.1"
    compile ":recaptcha:0.6.4"
    compile ":jasypt-encryption:1.1.0"
  }
}

codenarc {
  properties = {}
}

coverage {
  exclusions = []
  sourceInclusions = []
}

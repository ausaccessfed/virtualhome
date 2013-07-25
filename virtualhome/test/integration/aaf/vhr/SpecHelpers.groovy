package aaf.vhr

import org.codehaus.groovy.runtime.InvokerHelper

import grails.plugin.spock.*
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.apache.shiro.SecurityUtils

class SpecHelpers {
  
  static void setupShiroEnv(def s) {
    def subject = [ getPrincipal: { s.id }, isAuthenticated: { true }, isPermitted: { perm -> def res = false; s.permissions.each { if (it.target == perm) { res = true }}; res;} ] as org.apache.shiro.subject.Subject
    ThreadContext.put( ThreadContext.SECURITY_MANAGER_KEY, [ getSubject: { subject } ] as SecurityManager )
    SecurityUtils.metaClass.static.getSubject = { subject }
  }
  
}

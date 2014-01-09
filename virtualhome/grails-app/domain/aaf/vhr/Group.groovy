package aaf.vhr

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

import org.apache.shiro.SecurityUtils

@ToString(includeNames=true, includes="id, name")
@EqualsAndHashCode
class Group {
  static auditable = true

  String name
  String description
  String groupScope

  String welcomeMessage

  boolean totpForce       // All accounts must setup 2-Step Verification and can't opt out

  boolean active = true
  boolean blocked = false
  boolean archived = false
  
  Date dateCreated
  Date lastUpdated

  static hasMany = [subjects: ManagedSubject]

  static belongsTo = [organization:Organization]

  static constraints = {
    name(nullable: false, blank: false)
    description (nullable: false, blank:false)
    groupScope (nullable:true, unique: true, matches: "[a-zA-Z0-9]+")
    dateCreated(nullable:true)
    lastUpdated(nullable:true)

    welcomeMessage(nullable:true, markup:true)
  }

  static mapping = {
    table 'vhr_group'
    welcomeMessage type: "text"
  }

  public boolean canCreate(Organization owner) {
    SecurityUtils.subject.isPermitted("app:administrator") || 
    ( SecurityUtils.subject.isPermitted("app:manage:organization:${owner.id}:group:create") 
      && owner.functioning() )
  }

  public boolean canMutate() {
    SecurityUtils.subject.isPermitted("app:administrator") || 
    ( SecurityUtils.subject.isPermitted("app:manage:organization:${organization.id}:group:${id}:edit") 
      && !blocked && !archived && organization.functioning() )
  }

  public boolean canDelete() {
    SecurityUtils.subject.isPermitted("app:administrator")
  }

  public boolean functioning() {
    active && !archived && !blocked && organization.functioning()
  }

  public boolean enforceTwoStepLogin() {
    this.totpForce
  }
}

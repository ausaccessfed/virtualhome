package aaf.vhr

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

import org.apache.shiro.SecurityUtils

import aaf.base.identity.Role

@ToString(includeNames=true, includes="id, name, frID")
@EqualsAndHashCode
class Organization  {
  static auditable = true

  String name
  String displayName
  String description
  String orgScope

  long frID
  long subjectLimit 
  long groupLimit
  
  boolean active = false
  boolean blocked = false
  boolean archived = false
  boolean undergoingWorkflow = false

  List groups

  static hasMany = [subjects: ManagedSubject,
                    groups: Group]
  
  Date dateCreated
  Date lastUpdated

  static constraints = {
    name(nullable: false, blank: false)
    displayName(nullable: false, blank: false)
    description(nullable:true, blank: false, maxSize:2000)
    orgScope(nullable:true, unique: true, matches: "[a-zA-Z0-9]+")

    dateCreated(nullable:true)
    lastUpdated(nullable:true)
  }

  public boolean canCreate() {
    SecurityUtils.subject.isPermitted("app:administrator")
  }

  public boolean canMutate() {
    SecurityUtils.subject.isPermitted("app:administrator") || 
    ( SecurityUtils.subject.isPermitted("app:manage:organization:${id}:edit") 
      && !blocked && !archived )
  }

  public boolean canDelete() {
    SecurityUtils.subject.isPermitted("app:administrator")
  }

  public boolean functioning() {
    active && !archived && !blocked && !undergoingWorkflow 
  }

  public boolean canRegisterSubjects() {
    (subjectLimit == 0 || subjects.size() < subjectLimit) && functioning()
  }

  public boolean canRegisterGroups() {
    (groupLimit == 0 || groups.size() < groupLimit) && functioning()
  }

}

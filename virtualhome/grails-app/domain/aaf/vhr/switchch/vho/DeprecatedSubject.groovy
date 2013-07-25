package aaf.vhr.switchch.vho

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@ToString(includeNames=true, includes="id, subject")
@EqualsAndHashCode
class DeprecatedSubject {
  static auditable = true

  String login
  String password

  boolean migrated = false
  int migrationAttempts = 0
  
  Date dateCreated
  Date lastUpdated
}

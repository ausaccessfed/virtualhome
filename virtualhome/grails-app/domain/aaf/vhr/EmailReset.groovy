package aaf.vhr

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@ToString(includeNames=true, includes="id, subject")
@EqualsAndHashCode
class EmailReset {
  static auditable = true

  String code
  String hash
  String salt
  
  Date validUntil
  Date dateCreated
  Date lastUpdated

  static belongsTo = [subject:ManagedSubject]
  static constraints = {
    code nullable: false, blank:false, size: 24..24
    hash nullable: false, blank:false, size: 128..128
    salt nullable: false, blank:false, size: 29..29

    validUntil: nullable:false
  }

  String response
  static transients = ['response']
}

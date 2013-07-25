package aaf.vhr

import javax.persistence.*;
import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

import aaf.base.identity.Subject

@ToString(includeNames=true, includes="id, reason")
@EqualsAndHashCode
class StateChange {
  StateChangeType event

  String reason

  String category
  String environment  // unique information about the environment at the time the change was made

  Subject actionedBy

  Date dateCreated
  Date lastUpdated

  static belongsTo = [subject:ManagedSubject]

  static constraints = {
    actionedBy nullable:true
    category nullable:true
    environment nullable:true
  }

  static mapping = {
    environment type: "text"
  }
}

public enum StateChangeType {
  BLOCKED,
  UNBLOCKED, 
  LOCKED,
  UNLOCKED, 
  ACTIVATE, 
  DEACTIVATE,
  ARCHIVED,
  UNARCHIVED,
  LOGIN,
  FAILLOGIN,
  FAILCAPTCHA,
  FAILMULTIPLELOGIN,
  CHANGEPASSWORD,
  RECOVEREDLOSTPASSWORD
}

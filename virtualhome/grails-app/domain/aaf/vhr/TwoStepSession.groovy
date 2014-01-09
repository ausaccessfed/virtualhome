package aaf.vhr

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@ToString
@EqualsAndHashCode
class TwoStepSession {
  static auditable = true

  String value
  Date expiry

  static belongsTo = [managedSubject:ManagedSubject]
  static mapping = {
    value index: 'Value_Idx'
  }

  def populate() {
    value = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(64)
    expiry = new Date()
  }
}

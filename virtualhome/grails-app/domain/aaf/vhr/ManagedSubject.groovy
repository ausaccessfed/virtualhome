package aaf.vhr

import com.bloomhealthco.jasypt.GormEncryptedStringType

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

import aaf.base.identity.Subject
import org.apache.shiro.SecurityUtils

import groovy.time.TimeCategory

@ToString(includeNames=true, includes="id, login, cn, email")
@EqualsAndHashCode
class ManagedSubject {
  static auditable = true

  static final affiliations = [ 'affiliate',
                                'alum',
                                'employee',
                                'faculty',
                                'library-walk-in',
                                'member',
                                'staff',
                                'student'] as List

  String login
  String hash

  String totpKey              // 2-Step Verification (Time-base One Time Password), Used with Google Authenticator and simillar apps
  boolean totpForce           // This account must setup 2-Step Verification and can't opt out

  String apiKey               // Use for local account management context
  String eptidKey             // Used as input for EPTID generation so login changes don't impact us - should never be altered.

  // Password reset. Both codes required to be input, second provided via SMS or administrator
  String resetCode
  String resetCodeExternal

  // Last time the password reset codes were resent to the user. Used for throttling.
  Date lastCodeResend

  Date accountExpires

  // AAF Core
  String cn                   // oid:2.5.4.3
  String email                // oid:0.9.2342.19200300.100.1.3
  String sharedToken          // oid:1.3.6.1.4.1.27856.1.2.5
  String displayName          // oid:2.16.840.1.113730.3.1.241
  String eduPersonAssurance   // oid:1.3.6.1.4.1.5923.1.1.1.11
  String eduPersonAffiliation // oid:1.3.6.1.4.1.5923.1.1.1.1 - stored seperated by ; for IdP resolver simplification
  String eduPersonEntitlement // oid:1.3.6.1.4.1.5923.1.1.1.7 - stored seperated by ; for IdP resolver simplification

  // AAF Optional
  String givenName            // oid:2.5.4.42
  String surname              // oid:2.5.4.4
  String mobileNumber         // oid:0.9.2342.19200300.100.1.41
  String telephoneNumber      // oid:2.5.4.20
  String postalAddress        // oid:2.5.4.16
  String organizationalUnit   // oid:2.5.4.11

  boolean active = false
  boolean locked = false
  boolean blocked = false
  boolean archived = false

  Date dateCreated
  Date lastUpdated

  int failedLogins = 0
  int failedResets = 0

  List challengeResponse
  List emailReset

  static hasMany = [challengeResponse: ChallengeResponse,
                    emailReset: EmailReset,
                    invitations: ManagedSubjectInvitation,
                    stateChanges: StateChange,
                    twoStepSessions: TwoStepSession]

  static belongsTo = [organization:Organization,
                      group:Group]

  static constraints = {
    login nullable:true, blank: false, unique: true, size: 3..100,  validator: { val -> if (val?.contains(' ')) return 'value.contains.space' }
    hash nullable:true, blank:false, minSize:60, maxSize:60
    totpKey nullable:true
    
    resetCode nullable:true
    resetCodeExternal nullable:true, validator: {val, obj ->
      val == null || val != obj.resetCode
    }

    lastCodeResend nullable:true

    apiKey nullable:true, unique:true
    eptidKey nullable:true, unique:true

    accountExpires nullable:true 

    email blank:false, unique:true, email:true
    cn validator: {val, obj ->
      return (val != null && val != '' && (val.count(' ') == 0 || val.count(' ') == 1))
    }
    sharedToken nullable:false, blank: false, unique: true
    eduPersonEntitlement nullable:true, blank:false

    eduPersonAssurance inList: ['urn:mace:aaf.edu.au:iap:id:1',
                                'urn:mace:aaf.edu.au:iap:id:2',
                                'urn:mace:aaf.edu.au:iap:id:3',
                                'urn:mace:aaf.edu.au:iap:id:4']

    eduPersonAffiliation nullable:false, blank:false, maxSize: 255

    mobileNumber nullable: true, blank: false, validator: validMobileNumber
    givenName nullable: true, blank: false          
    surname nullable: true, blank: false            
    telephoneNumber nullable: true, blank: false   
    postalAddress nullable: true, blank: false      
    organizationalUnit nullable: true, blank: false 

    organization nullable: false
    group nullable: false
  }

  static mapping = {
    eduPersonEntitlement type: "text"
    totpKey type: GormEncryptedStringType
  }

  def beforeValidate() {
    if(!eptidKey)
      this.@eptidKey = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(12)

    if(!apiKey)
      this.@apiKey = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(16)
  }

  String plainPassword
  String plainPasswordConfirmation
  static transients = ['plainPassword', 'plainPasswordConfirmation']

  public boolean canCreate(Group owner) {
    SecurityUtils.subject.isPermitted("app:administrator") || 
    ( SecurityUtils.subject.isPermitted("app:manage:organization:${owner.organization.id}:group:${owner.id}:managedsubject:create") 
      && owner.functioning() )
  }

  public boolean canMutate() {
    SecurityUtils.subject.isPermitted("app:administrator") || 
    ( SecurityUtils.subject.isPermitted("app:manage:organization:${organization.id}:group:${group.id}:managedsubject:${id}:edit") 
      && !archived && !blocked && group.functioning() )
  }

  public boolean canDelete() {
    SecurityUtils.subject.isPermitted("app:administrator")
  }

  public boolean canShow() {
    SecurityUtils.subject.isPermitted("app:manage:organization:${organization.id}:group:${group.id}:managedsubject:show")
  } 

  public boolean canChangePassword() {
    !locked && !blocked && !archived && organization?.functioning() && group?.functioning()
  }

  public boolean canLogin() {
    hash && this.functioning()
  }

  public boolean requiresLoginCaptcha() {
    this.failedLogins > 2
  }

  public boolean isUsingTwoStepLogin() {
    this.totpKey != null
  }

  public boolean enforceTwoStepLogin() {
    this.totpForce || group.enforceTwoStepLogin()
  }

  public boolean hasEstablishedTwoStepLogin(String sessionID) {
    use (TimeCategory) {
      def twoStepSession = twoStepSessions?.find{ it?.value == sessionID }
      (twoStepSession && twoStepSession.expiry > 90.days.ago)
    }
  }

  public TwoStepSession establishTwoStepSession() {
    def session = new TwoStepSession()
    session.populate()

    this.addToTwoStepSessions(session)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when adding TwoStep session"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when adding TwoStep session")
    }

    session
  }

  public void cleanupEstablishedTwoStepLogin() {
    use (TimeCategory) {
      twoStepSessions?.each { twoStepSession ->
        if(twoStepSession && twoStepSession?.expiry < 90.days.ago)
          twoStepSession.delete()
      }
    }
  }

  public boolean functioning() {
    active && !isExpired() && !locked && !blocked && !archived && group?.functioning()
  }

  public boolean isExpired() {
    if(!accountExpires)
      return false

    def now = new Date()
    now.after(accountExpires)
  }

  public boolean isFinalized() {
    login != null && hash != null
  }

  public void setResetCode(String resetCode) {
    if(resetCode)
      this.resetCode = cleanCode(resetCode)
    else
      this.resetCode = null
  }

  public void setResetCodeExternal(String resetCodeExternal) {
    if(resetCodeExternal)
      this.resetCodeExternal = cleanCode(resetCodeExternal)
    else
      this.resetCodeExternal = null
  }

  public lock(String reason, String category, String environment, Subject actionedBy) {
    this.locked = true

    def lockChange = new StateChange(event:StateChangeType.LOCKED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(lockChange)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting locked state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting locked state")
    }
  }

  public unlock(String reason, String category, String environment, Subject actionedBy) {
    this.locked = false
    this.failedResets = 0

    def lockChange = new StateChange(event:StateChangeType.UNLOCKED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(lockChange)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting unlocked state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting unlocked state")
    }
  }

  public block(String reason, String category, String environment, Subject actionedBy) {
    this.blocked = true

    def blockChange = new StateChange(event:StateChangeType.BLOCKED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(blockChange)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting blocked state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting blocked state")
    }
  }

  public unblock(String reason, String category, String environment, Subject actionedBy) {
    this.blocked = false
    this.failedResets = 0

    def blockChange = new StateChange(event:StateChangeType.UNBLOCKED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(blockChange)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting unblocked state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting unblocked state")
    }
  }

  public activate(String reason, String category, String environment, Subject actionedBy) {
    this.active = true
    this.failedLogins = 0

    def change = new StateChange(event:StateChangeType.ACTIVATE, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting active state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting active state")
    }
  }

  public deactivate(String reason, String category, String environment, Subject actionedBy) {
    this.active = false

    def change = new StateChange(event:StateChangeType.DEACTIVATE, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting deactive state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting deactive state")
    }
  }

  public archive(String reason, String category, String environment, Subject actionedBy) {
    this.archived = true

    def change = new StateChange(event:StateChangeType.ARCHIVED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting archive state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting archive state")
    }
  }

  public unarchive(String reason, String category, String environment, Subject actionedBy) {
    this.archived = false

    def change = new StateChange(event:StateChangeType.UNARCHIVED, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting deactive state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting deactive state")
    }
  }

  public failCaptcha(String reason, String category, String environment, Subject actionedBy) {
    def change = new StateChange(event:StateChangeType.FAILCAPTCHA, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting failCaptcha state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting failCaptcha state")
    }
  }

  public failLogin(String reason, String category, String environment, Subject actionedBy) {
    this.failedLogins++

    if(failedLogins >= 5) {
      def change = new StateChange(event:StateChangeType.FAILMULTIPLELOGIN, reason:"$reason Reached login attempts limit, account deactivated", category:category, environment:environment, actionedBy:actionedBy)
      this.addToStateChanges(change)

      this.active = false     // prevent future auth attempts until unlocked by admin
    } else {
      def change = new StateChange(event:StateChangeType.FAILLOGIN, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
      this.addToStateChanges(change)
    }

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting failLogin state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting failLogin state")
    }
  }

  public successfulLogin(String reason, String category, String environment, Subject actionedBy) {
    this.failedLogins = 0

    def change = new StateChange(event:StateChangeType.LOGIN, reason:reason, category:category, environment:environment, actionedBy:actionedBy)
    this.addToStateChanges(change)

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting successfulLogin state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting successfulLogin state")
    }
  }

  public successfulLostPassword() {
    active = true

    resetCode = null
    resetCodeExternal = null

    failedResets = 0
    failedLogins = 0

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when setting successfulLostPassword state"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when setting successfulLostPassword state")
    }
  }

  public increaseFailedResets() {
    this.failedResets++

    if(!this.save(flush:true)) {
      log.error "Unable to save $this when increasing failed resets"
      this.errors.each {
        log.error it
      }
      throw new RuntimeException ("Unable to save $this when increasing failed resets")
    }
  }

  private String cleanCode(String code) {
    // Ensure no confusion on SMS/Email codes between
    // characters that look the same - extend as

    if (code.contains('I')) {
      code = code.replace('I', 'i')
    }
    if(code.contains('l')) {
      code = code.replace('l', 'L')
    }
    if(code.contains('O')) {
      code = code.replace('O', 'o')
    }
    if(code.contains('0')) {
      code = code.replace('0', '9')
    }

    code
  }

  static validMobileNumber = { value, obj ->
    if(value == "" || value == null) {
      obj.mobileNumber = null
      return true
    }

    def checkedNumber = value

    // Translate Australian numbers to international format
    if(checkedNumber.startsWith('04')) {
      checkedNumber = checkedNumber[1..-1]
      checkedNumber = "+61$checkedNumber"
    }

    checkedNumber = checkedNumber.replace(' ','')

    if(!checkedNumber.startsWith('+')) {
      return false
    } else {
      obj.mobileNumber = checkedNumber
      return true
    }
  }
}

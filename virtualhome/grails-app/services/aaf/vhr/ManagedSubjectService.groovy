package aaf.vhr

import org.springframework.context.i18n.LocaleContextHolder
import org.apache.commons.validator.EmailValidator

import org.apache.shiro.SecurityUtils

import groovy.time.TimeCategory

import aaf.base.admin.EmailTemplate

class ManagedSubjectService {

  boolean transactional = true
  def grailsApplication
  def messageSource

  def sharedTokenService
  def emailManagerService
  def passwordValidationService
  def cryptoService

  private final String TOKEN_COUNT = 'aaf.vhr.managedsubjectservice.registerfromcsv.invalidtokens'
  private final String TOKEN_CN = 'aaf.vhr.managedsubjectservice.registerfromcsv.invalidcn'
  private final String TOKEN_EMAIL = 'aaf.vhr.managedsubjectservice.registerfromcsv.invalidemail'
  private final String TOKEN_EMAIL_UNIQUENESS = 'aaf.vhr.managedsubjectservice.registerfromcsv.emailconflict'
  private final String TOKEN_AFFILIATION ='aaf.vhr.managedsubjectservice.registerfromcsv.invalidaffiliation'
  private final String TOKEN_EXPIRY ='aaf.vhr.managedsubjectservice.registerfromcsv.expiry'
  private final String TOKEN_LOGIN = 'aaf.vhr.managedsubjectservice.registerfromcsv.invalidlogin'
  private final String TOKEN_PASSWORD = 'aaf.vhr.managedsubjectservice.registerfromcsv.invalidpassword'

  private final String TOKEN_EMAIL_SUBJECT ='aaf.vhr.managedsubjectservice.registered.email.subject'

  private final String INVITATION_INVALID ='aaf.vhr.managedsubjectservice.finalize.invitation.invalid'

  public static final String[] AFFILIATIONS = [ 'faculty', 'student', 'staff', 'alum', 'member', 
                                                'affiliate', 'employee', 'library-walk-in' ]

  public static final String DEFAULT_ASSURANCE = 'urn:mace:aaf.edu.au:iap:id:1'

  def finalize(ManagedSubjectInvitation invitation, String login, String plainPassword, String plainPasswordConfirmation, String mobileNumber) {
    def managedSubject = invitation.managedSubject

    if(invitation.utilized || managedSubject.login != null)
      return [false, messageSource.getMessage(INVITATION_INVALID, [] as Object[], INVITATION_INVALID, LocaleContextHolder.locale)]

    managedSubject.login = login
    managedSubject.plainPassword = plainPassword
    managedSubject.plainPasswordConfirmation = plainPasswordConfirmation
    managedSubject.mobileNumber = mobileNumber
    
    def (valid, errors) = passwordValidationService.validate(managedSubject)
    if(!valid) {
      log.warn "Unable to finalize $managedSubject as password is invalid"
      return [false, managedSubject]
    }

    cryptoService.generatePasswordHash(managedSubject)

    if(!managedSubject.validate()) {
      log.warn "Unable to finalize $managedSubject as data is invalid"

      managedSubject.errors.each {
        log.warn it
      }
      
      return [false, managedSubject]
    }

    managedSubject.active = true
    
    if(!managedSubject.save()) {
      log.error "Failed trying to save $managedSubject when finalizing"
      managedSubject.errors.each {
        log.warn it
      }

      throw new RuntimeException("Failed trying to save $managedSubject when finalizing")  // Rollback transaction
    }

    invitation.utilized = true
    if(!invitation.save()) {
      log.error "Failed trying to save $invitation when finalizing $managedSubject"
      managedSubject.errors.each {
        log.warn it
      }

      throw new RuntimeException("Failed trying to save $invitation when finalizing $managedSubject")  // Rollback transaction
    }

    // Clean up any unused invitations
    //ManagedSubjectInvitation.findAllWhere(managedSubject:managedSubject, utilized:false)*.delete()

    log.info "Finalized the account for $managedSubject - they are now ready to use VHR"
    return [true, managedSubject]
  }

  def register(ManagedSubject managedSubject, boolean confirm = true) {
    if(!managedSubject.save()) {
      log.error "Failed trying to save $managedSubject"
      managedSubject.errors.each {
        log.warn it
      }

      throw new RuntimeException("Failed trying to save $managedSubject")  // Rollback transaction
    }

    if(confirm)
      sendConfirmation(managedSubject)

    managedSubject
  }

  def registerFromCSV(Group group, byte[] csv) {

    def emailValidator = EmailValidator.getInstance()

    def valid = true
    def errors = [] as List
    def subjects = [] as List

    def lc = 0

    def reservedEmails = [:]

    ByteArrayInputStream is = new ByteArrayInputStream(csv)
    is.eachCsvLine { tokens ->
      lc++

      // Ensure required pii
      if(tokens.size() != 4 && tokens.size() != 6) {
        valid = false
        errors.add(messageSource.getMessage(TOKEN_COUNT, [lc] as Object[], TOKEN_COUNT, LocaleContextHolder.locale))
      } else {
        // For some reason this causes an ArrayIndexOutOfBoundsException if we have a
        // mismatch in the number of arguments. Which is odd, because this is a documented
        // use case: http://groovy.codehaus.org/Multiple+Assignment
        def (cn, email, affiliation, expiry, login, password) = tokens + [null,null]

        // Only if we have the correct number of tokens do we look at actual content
        // Ensure cn format
        if(cn.size() < 1 || cn.count(' ') > 1) {
          valid = false
          errors.add(messageSource.getMessage(TOKEN_CN, [lc, cn] as Object[], TOKEN_CN, LocaleContextHolder.locale))
        }

        // Ensure email format
        if(email.size() < 1 || !emailValidator.isValid(email)) {
          valid = false
          errors.add(messageSource.getMessage(TOKEN_EMAIL, [lc, email] as Object[], TOKEN_EMAIL, LocaleContextHolder.locale))
        }

        if(reservedEmails.containsKey(email)) {
          valid = false
          errors.add(messageSource.getMessage(TOKEN_EMAIL_UNIQUENESS, [lc, email, reservedEmails[email]] as Object[], TOKEN_EMAIL_UNIQUENESS, LocaleContextHolder.locale))
        } else {
          reservedEmails[email] = lc
        }

        // Ensure affiliation
        if(affiliation.size() < 1 || !ManagedSubjectService.AFFILIATIONS.contains(affiliation)) {
          valid = false
          errors.add(messageSource.getMessage(TOKEN_AFFILIATION, [lc, affiliation] as Object[], TOKEN_AFFILIATION, LocaleContextHolder.locale))
        }

        // Ensure expiry
        if(expiry.size() < 1 || !expiry.isNumber()){
          valid = false
          errors.add(messageSource.getMessage(TOKEN_EXPIRY, [lc, expiry] as Object[], TOKEN_EXPIRY, LocaleContextHolder.locale))
        }

        if(login && password) {
          if(SecurityUtils.subject.isPermitted("app:administrator")) {
            // Ensure login
            if(login.size() < 1){
              valid = false
              errors.add(messageSource.getMessage(TOKEN_LOGIN, [lc, login] as Object[], TOKEN_LOGIN, LocaleContextHolder.locale))
            }

            // Ensure password
            if(password.size() < 8) {
              valid = false
              errors.add(messageSource.getMessage(TOKEN_PASSWORD, [lc, password] as Object[], TOKEN_PASSWORD, LocaleContextHolder.locale))
            }
          } else {
            // for non admins report token size error so login/password functionality isn't leaked
            valid = false
            errors.add(messageSource.getMessage(TOKEN_COUNT, [lc, cn] as Object[], TOKEN_COUNT, LocaleContextHolder.locale))
          }
        }
      }
    }

    is.close()  // a no-op but incase this changes in the future

    if(!valid) {
      log.error "Unable to process CSV uploaded by $subject"
      errors.each {
        log.info it
      }
      return [false, errors, null, lc]
    }

    // Valid CSV data, create ManagedSubjects
    lc = 0
    is = new ByteArrayInputStream(csv)
    is.eachCsvLine { tokens ->
      def (cn, email, affiliation, expiry, login, password) = tokens + [null, null]
      lc++

      def managedSubject = new ManagedSubject(cn:cn, email:email, eduPersonAffiliation:affiliation, active:false, displayName:cn, eduPersonAssurance: DEFAULT_ASSURANCE, organization:group.organization, group:group)
      sharedTokenService.generate(managedSubject)

      if(expiry.toInteger() > 0) {
        use(TimeCategory) {
          Date now = new Date()
          managedSubject.accountExpires = now + expiry.toInteger().months
        }
      }

      if(!managedSubject.validate()) {
        valid = false
      }

      if(tokens.size() == 6) {
        managedSubject.active = true
        managedSubject.login = login
        managedSubject.plainPassword = password
        managedSubject.plainPasswordConfirmation = password

        if(!managedSubject.validate()) {
          valid = false
        }

        def (validPassword, passwordErrors) = passwordValidationService.validate(managedSubject)
        if(!validPassword) {
          log.error "Error in password supplied for $managedSubject"
          valid = false
        } else {
          cryptoService.generatePasswordHash(managedSubject)
        }
      }

      subjects.add(managedSubject)
    }

    if(valid) {
      // There is of course a small chance that someone else could create a ManagedSubject
      // with the same values in the interim but it is unlikely.
      subjects.each { managedSubject ->
        managedSubject = register(managedSubject, false)
        log.info "Created $managedSubject from CSV file submitted by $subject"
      }

      log.info "Created all subjects from CSV file submitted by $subject"
      subjects.each { ms ->
        if(!ms.login) {
          log.info "Email account information and further instructions to $ms"
          sendConfirmation(ms)
        } else {
          log.info "As account $ms has been provided login and password no email details where sent."
        }
      }

      return [true, errors, subjects, lc]
    }
    
    [false, errors, subjects, lc]
  }

  public void sendConfirmation(ManagedSubject managedSubject) {
    def emailSubject = messageSource.getMessage(TOKEN_EMAIL_SUBJECT, [] as Object[], TOKEN_EMAIL_SUBJECT, LocaleContextHolder.locale)
    def emailTemplate = EmailTemplate.findWhere(name:"registered_managed_subject")

    if(!emailTemplate) {
      throw new RuntimeException("Email template for creating new ManagedSubjects 'registered_managed_subject' does not exist")  // Rollback transaction
    }

    def invitation = new ManagedSubjectInvitation(managedSubject:managedSubject)
    if(!invitation.save()) {
      log.error "Failed to create invitation code for $managedSubject aborting"
      invitation.errors.each {
        log.warn it
      }
      throw new RuntimeException("Failed to create invitation code for $managedSubject aborting")  // Rollback transaction
    }
    emailManagerService.send(managedSubject.email, emailSubject, emailTemplate, [managedSubject:managedSubject, invitation:invitation]) 
  }

}

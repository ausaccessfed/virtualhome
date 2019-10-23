package aaf.vhr

import edu.vt.middleware.password.*
import edu.vt.middleware.dictionary.*
import edu.vt.middleware.dictionary.sort.*

class PasswordValidationService {
  boolean transactional = true
  def grailsApplication
  def cryptoService

  Properties msgs

  public PasswordValidationService() {
    msgs = new Properties()
    msgs.load(getClass().getResourceAsStream("passwordvalidation.txt"))
  }

  /*
    @pre: The ManagedSubject plainPassword and plainPasswordConfirm
    values have been populated with a plain text representation
    of the password attempting to be set by the subject

    The AAF decided on Tuesday 3/12/2013 in a planning meeting
    to reduce the restrictions on passwords (along with other measures)
    due to support issues that have been encountered. Issue: #146

    We enforce:
      All passwords:
      Do not contain the login name
      Minimum length 8 char

      Password is 8 - 15 char:
      * No whitespace;
      * At least 1 number;
      * At least 1 Uppercase character; and
      * At least 1 Lowercase chatacter

      Password is 16 char or greater:
      * Minimum length of 16 char only
  */
  def validate(ManagedSubject subject) {
    if(subject.plainPassword != subject.plainPasswordConfirmation) {
      log.warn("The submitted plaintext passwords for $subject don't match, rejecting.")
      subject.errors.rejectValue('plainPassword', 'aaf.vhr.passwordvalidationservice.notmatching')
      subject.discard()
      return [false, ['aaf.vhr.passwordvalidationservice.notmatching'], subject]
    }

    if(subject.plainPassword.toLowerCase().contains(subject.login.toLowerCase())) {
      log.warn("The submitted plaintext passwords for $subject contains the username, rejecting.")
      subject.errors.rejectValue('plainPassword', 'aaf.vhr.passwordvalidationservice.containslogin')
      subject.discard()
      return [false, ['aaf.vhr.passwordvalidationservice.containslogin'], subject]
    }

    if(subject.hash != null) {
      if(cryptoService.verifyPasswordHash(subject.plainPassword, subject)) {
        log.warn("The submitted plaintext password for $subject is the same as the current value, rejecting.")
        subject.errors.rejectValue('plainPassword', 'aaf.vhr.passwordvalidationservice.reused')
        subject.discard()
        return [false, ['aaf.vhr.passwordvalidationservice.reused'], subject]
      }
    }

    def pw = subject.plainPassword

    MessageResolver resolver = new MessageResolver(msgs)

    WhitespaceRule whitespaceRule = new WhitespaceRule()

    List<Rule> ruleList = new ArrayList<Rule>()

    if(pw.length() < 16) {
      LengthRule lengthRule = new LengthRule()
      lengthRule.minimumLength = 8

      CharacterCharacteristicsRule charRule = new CharacterCharacteristicsRule()
      charRule.getRules().add(new DigitCharacterRule(1))
      charRule.getRules().add(new UppercaseCharacterRule(1))
      charRule.getRules().add(new LowercaseCharacterRule(1))
      charRule.setNumberOfCharacteristics(3)

      ruleList.add(whitespaceRule)
      ruleList.add(lengthRule)
      ruleList.add(charRule)
    } else {
      LengthRule lengthRule = new LengthRule()
      lengthRule.minimumLength = 16

      ruleList.add(lengthRule)
    }

    PasswordValidator validator = new PasswordValidator(resolver, ruleList)
    PasswordData passwordData = new PasswordData(new Password(pw))

    RuleResult result = validator.validate(passwordData)

    if(result.isValid()) {
      log.info "New password valid for ${subject}"
      [true, null]
    }
    else {
      validator.getMessages(result).unique().each { e ->
        // We don't want to double on error messages for CharacterCharacteristicsRule it confuses users
        if(!e.equals('aaf.vhr.passwordvalidationservice.insufficent.characters')) {
          subject.errors.rejectValue('plainPassword', e)
          log.info "Password error for ${subject}: $e"
        }
      }
      subject.discard()
      [false, validator.getMessages(result)]
    }
  }
}

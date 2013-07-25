package aaf.vhr

import org.apache.shiro.crypto.hash.Sha512Hash
import aaf.vhr.crypto.BCrypt

class CryptoService {
  boolean transactional = true
  def grailsApplication

  /*
    The modular crypt format for bcrypt consists of:

    1.  $2a$ identifying the hashing algorithm and format
    2.  A two digit value denoting the cost parameter, followed by $
    3.  A 53 characters long base-64-encoded value (using the alphabet ., /, 0–9, A–Z, a–z 
        that is different to the standard Base 64 Encoding alphabet) consisting of:
          22 characters of salt (effectively only 128 bits)
          31 characters of encrypted output (effectively only 184 bits)
    
    This library doesn't limit the password to 72 characters or less it simply 
    lets it pass silently. A 72 characters bCrypted password is better than the fast 
    hashing alternative.

    For gensalt provide a value of between 4 and 31. This should be increased in
    configuration over time as server power increases.

    @pre: Subject.plainPassword is non null, non blank and meets any min length requirements
    of the caller.
  */
  public void generatePasswordHash(ManagedSubject subject) {
    def salt = BCrypt.gensalt(grailsApplication.config.aaf.vhr.crypto.log_rounds)
    def hash = BCrypt.hashpw(subject.plainPassword, salt)
    subject.hash = hash
  }

  /*
    @pre: plainPassword is non null, subject.hash is populated and was created by generatePasswordHash
  */
  public boolean verifyPasswordHash(String plainPassword, ManagedSubject subject) {
    BCrypt.checkpw(plainPassword, subject.hash)
  }

  /*
    SHA-512 for hashing challenge response answers.

    @pre: challengeResponse.response is non null, non blank and meets any min length requirements
    of the caller.
  */
  public void generateChallengeResponseHash(ChallengeResponse challengeResponse) {
    // We use BCrypt salt generation for convenience
    challengeResponse.salt = BCrypt.gensalt(grailsApplication.config.aaf.vhr.crypto.log_rounds)
    def hash = new Sha512Hash(challengeResponse.response, challengeResponse.salt, grailsApplication.config.aaf.vhr.crypto.sha_rounds)  
    challengeResponse.hash = hash.toString()
  }

  /*
    Verify using SHA-512 for challenge response answers.

    @pre: challengeResponse is non null, non blank and meets any min length requirements
    of the caller.
  */
  public boolean verifyChallengeResponseHash(String response, ChallengeResponse challengeResponse) {
    def hash = new Sha512Hash(response, challengeResponse.salt, grailsApplication.config.aaf.vhr.crypto.sha_rounds)  
    challengeResponse.hash == hash.toString()
  }

  /*
    SHA-512 for hashing email reset codes.

    @pre: emailReset is non null
  */
  public void generateEmailResetHash(EmailReset emailReset) {
    emailReset.code = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(24)
    // We use BCrypt salt generation for convenience
    emailReset.salt = BCrypt.gensalt(grailsApplication.config.aaf.vhr.crypto.log_rounds)
    def hash = new Sha512Hash(emailReset.code, emailReset.salt, grailsApplication.config.aaf.vhr.crypto.sha_rounds)  
    emailReset.hash = hash.toString()
  }

  /*
    Verify using SHA-512 for email reset codes.

    @pre: emailReset is non null and has subject it is associated with populated
    by the caller.
  */
  public boolean verifyEmailResetHash(String code, EmailReset emailReset) {
    def hash = new Sha512Hash(code, emailReset.salt, grailsApplication.config.aaf.vhr.crypto.sha_rounds)  
    emailReset.hash == hash.toString()
  }
}

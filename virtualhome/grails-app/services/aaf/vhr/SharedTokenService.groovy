package aaf.vhr

import org.apache.shiro.crypto.hash.Sha1Hash

class SharedTokenService {
  boolean transactional = true
  def grailsApplication

  public String generate(ManagedSubject subject) {
    String entityID = grailsApplication.config.aaf.vhr.sharedtoken.idp_entityid
    String salt = aaf.vhr.crypto.CryptoUtil.randomAlphanumeric(24)

    String input = "${subject.login}/$entityID"
    def hash = new Sha1Hash(input, salt, grailsApplication.config.aaf.vhr.sharedtoken.sha_rounds)

    subject.sharedToken = format(hash.bytes.encodeBase64().toString())
  }

  /*
    Format according to CAUDIT attribute committee requirements

    Format: 27 character PEM “Base 64 Encoding with URL and Filename Safe Alphabet” 
    encoded string from a 160-bit SHA1 hash of a globally unique string. 
    Padding character, ‘=’, is removed from the value.

    See: http://tools.ietf.org/html/rfc4648#section-5
  */
  private format(String input){
    String aepst = input

    if (aepst.contains("/"))
      aepst = aepst.replaceAll("/", "_");

    if (aepst.contains("+"))
      aepst = aepst.replaceAll("\\+", "-");

    if (aepst.contains("="))
      aepst = aepst.replaceAll("=", "");

    return aepst;
  }
}

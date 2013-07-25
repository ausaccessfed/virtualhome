 package aaf.vhr.crypto;

 import java.security.SecureRandom;
 import java.util.Random;

 public class CryptoUtil {

  private static final SecureRandom SECUERANDOM = new SecureRandom();

  public static String randomAlphanumeric(int count) {
    return org.apache.commons.lang.RandomStringUtils.random(count, 0, 0, true, true, null, SECUERANDOM);
  }

}

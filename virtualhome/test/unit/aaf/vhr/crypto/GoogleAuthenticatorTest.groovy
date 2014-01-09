package aaf.vhr.crypto;

import java.util.List;
import java.util.ArrayList;

public class GoogleAuthenticatorTest extends grails.test.GrailsUnitTestCase {

  public void testGenerateSecret() {
    String secret = GoogleAuthenticator.generateSecretKey();
    String qrURL = GoogleAuthenticator.getQRBarcodeURL('testuser', 'vhr.test.edu.au', secret)

    println secret
    println qrURL

    assert secret.length() == 16
    assert qrURL == "https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth://totp/testuser@vhr.test.edu.au%3Fsecret%3D" + secret
  }

  /*
  If you want to test this register your device with the QR code at:
  https://www.google.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth://totp/testuser@vhr.test.edu.au%3Fsecret%3DLAZLDDYD4WYSDULO

  Then enable here providing the code it outputs.

  Haccccccky at best.

  public void testCheckCode() {
    assert (GoogleAuthenticator.checkCode('DPS6XA5YWTZFQ4FI', 980964, System.currentTimeMillis()) == true)
  }
  */
}

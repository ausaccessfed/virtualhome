package aaf.vhr.crypto;

import java.util.List;
import java.util.ArrayList;

public class CryptoUtilTest extends grails.test.GrailsUnitTestCase {

  public void testRandomAlphanumeric() {
    List<String> outputs = new ArrayList<String>();
    for (int i = 0; i < 100; i++) {
      String out = CryptoUtil.randomAlphanumeric(200);
      assertEquals(200, out.length());
      assertFalse(outputs.contains(out));
      outputs.add(out);
    }

    assertEquals(100, outputs.size());
  }

}

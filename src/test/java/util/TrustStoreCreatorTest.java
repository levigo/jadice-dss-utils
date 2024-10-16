package util;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

import org.jadice.signature.dss.util.TrustStoreCreator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TrustStoreCreatorTest {

  @Test
  public void testThat_trustStoreCreator_createsTrustStore() throws URISyntaxException {
    String string = Paths.get(this.getClass().getResource("/").toURI()).toString();
    File target = new File(string, "/trustStoreTestFile.p12");
    TrustStoreCreator.create(target, "somePassword", "PKCS12", Collections.emptyList());
    Assertions.assertTrue(target.exists());
  }


}

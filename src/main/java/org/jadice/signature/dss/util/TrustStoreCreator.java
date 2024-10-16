package org.jadice.signature.dss.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.jadice.util.log.LoggerFactory;
import org.jadice.util.log.qualified.QualifiedLogger;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;

/**
 * <p>
 * This class can be used to generate a truststore which holds the officially by the eu released
 * trusted certificates. This is based on the list of trusted lists which contains lists released by
 * the countries pointing to certificates.
 * </p>
 * <p>
 * Depending on the java version this file is executed with some trusted lists cannot be parsed. The
 * most can be parsed with java 21. This behaviour seems to happen because different java versions
 * provide different jdk/lib/security/cacerts files. So far only java 17 seems to have different
 * results, 11 and 21 are looking good.
 * </p>
 * <p>
 * However, if you want more information about what the dss library is doing add slf4j to the
 * classpath for debugging. More information about dss and the usage can be found under <a href=
 * "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html">DSS
 * cookbook</a>
 * </p>
 */
public class TrustStoreCreator {

  private static final QualifiedLogger LOGGER = LoggerFactory.getQualifiedLogger(TrustStoreCreator.class);
  // These are not confidential data. These are simply the parameters that were used to convert the
  // pem certificate data to a p12 keyStore (see below comments in createEuropeanLOTL.
  private static final String OJ_KEYSTORE_TYPE = "PKCS12";
  private static final String OJ_KEYSTORE_PASSWORD = "oj-password";
  private static final String OJ_KEYSTORE_FILE = "/oj-keystore.p12";

  private static final String LOTL_CACHE_DIR = System.getProperty("java.io.tmpdir") + "dss-tsl-loader-jadice";
  private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
  private static final String OFFICIAL_JOURNAL_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";


  private TrustStoreCreator() {
  }

  public static void create(File trustStoreFile, String trustStorePassword, String trustStoreType,
      List<String> trustedLists) {
    // Create a list in which the certificates are put
    TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
    // Create a job
    TLValidationJob job = createJob(tslCertificateSource, trustedLists);
    // Perform the actual loading of the certificate
    job.onlineRefresh();
    // write the trustStore
    writeTrustStore(tslCertificateSource, trustStoreFile, trustStoreType, trustStorePassword);
    // clean up the cache dir after we are done
    deleteCacheDir(new File(LOTL_CACHE_DIR));
  }

  private static void deleteCacheDir(File fileToDelete) {
    File[] allContents = fileToDelete.listFiles();
    if (allContents != null) {
      for (File file : allContents) {
        deleteCacheDir(file);
      }
    }
    fileToDelete.delete();
  }

  private static TLValidationJob createJob(TrustedListsCertificateSource tslCertificateSource,
      List<String> trustedLists) {
    TLValidationJob job = new TLValidationJob();
    FileCacheDataLoader onlineLoader = onlineLoader();
    job.setOnlineDataLoader(onlineLoader);
    job.setOfflineDataLoader(new FileCacheDataLoader());
    // pass the list that will hold the certificates
    job.setTrustedListCertificateSource(tslCertificateSource);
    job.setSynchronizationStrategy(new AcceptAllStrategy());

    if (trustedLists.isEmpty()) {
      // if no list was provided we use the lotl of the eu which includes all trusted lists
      LOTLSource europeanLOTL = createEuropeanLOTL();
      job.setListOfTrustedListSources(europeanLOTL);
    } else {
      List<TLSource> sources = new ArrayList<>();
      for (String trustedList : trustedLists) {
        TLSource tlSource = new TLSource();
        tlSource.setCertificateSource(tslCertificateSource);
        tlSource.setUrl(trustedList);
        sources.add(tlSource);
      }
      job.setTrustedListSources(sources.toArray(new TLSource[0]));
    }

    return job;
  }

  private static FileCacheDataLoader onlineLoader() {
    FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
    onlineFileLoader.setCacheExpirationTime(0);
    CommonsDataLoader dl = new CommonsDataLoader();
    dl.setTimeoutConnection(5000);
    dl.setTimeoutConnectionRequest(5000);
    dl.setRedirectsEnabled(true);
    onlineFileLoader.setDataLoader(dl);

    // We need to specify a cache directory
    File tslCache = new File(LOTL_CACHE_DIR);
    onlineFileLoader.setFileCacheDirectory(tslCache);
    return onlineFileLoader;
  }

  private static LOTLSource createEuropeanLOTL() {
    LOTLSource lotlSource = new LOTLSource();
    // This is a from the eu official released list of trusted list
    lotlSource.setUrl(LOTL_URL);
    // The keystore is released by the office journal (oj) of the eu. It contains the certificates that
    // were used to sign the lotl above. We need to add it so we can verify the lotl and their pivot
    // lotls (basically older versions of the lotl)
    lotlSource.setCertificateSource(officialJournalContentKeyStore());
    // This as far as I understand basically the url where the keystore above is published. The
    // published format there is the pem format. To convert it into a p12 format the following command
    // can be used:
    // openssl pkcs12 -export -nokeys -out ojKeystore.p12 -in keystore.pem -passout pass:oj-password
    lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(
        OFFICIAL_JOURNAL_URL));
    lotlSource.setPivotSupport(true);
    return lotlSource;
  }

  private static CertificateSource officialJournalContentKeyStore() {
    return new KeyStoreCertificateSource(TrustStoreCreator.class.getResourceAsStream(OJ_KEYSTORE_FILE),
        OJ_KEYSTORE_TYPE, OJ_KEYSTORE_PASSWORD.toCharArray());
  }

  private static void writeTrustStore(TrustedListsCertificateSource tslCertificateSource, File trustStoreFile,
      String trustStoreType, String trustStorePassword) {
    try {
      if (!trustStoreFile.exists()) {
        trustStoreFile.createNewFile();
      }

      KeyStore pkcs12 = KeyStore.getInstance(trustStoreType);
      // needed to initialize the keystore
      pkcs12.load(null, trustStorePassword.toCharArray());
      for (CertificateToken token : tslCertificateSource.getCertificates()) {
        pkcs12.setCertificateEntry(token.getDSSIdAsString().toLowerCase(Locale.ROOT), token.getCertificate());
      }
      try (FileOutputStream fos = new FileOutputStream(trustStoreFile)) {
        pkcs12.store(fos, trustStorePassword.toCharArray());
      }
    } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
      LOGGER.error("Unable to create keystore ", e);
    }
  }


}

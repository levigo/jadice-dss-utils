package org.jadice.dss.util;

import java.io.File;
import java.util.ArrayList;

/**
 * This class creates a default truststore with the EU certificates
 */
public class DefaultCreator {

  public static void main(String[] args) {
    System.out.println("Creating jadice DSS trust store...");
    TrustStoreCreator.create(new File("default.p12"), "jadice", "JKS", new ArrayList<>());
  }
}

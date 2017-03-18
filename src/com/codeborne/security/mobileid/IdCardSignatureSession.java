package com.codeborne.security.mobileid;

import java.io.Serializable;

import static java.lang.Integer.parseInt;

public class IdCardSignatureSession implements Serializable {

  private static final long serialVersionUID = 8149193185518071327L;

  public final int sessCode;
  public final String signatureId;
  public final String hash;

  public IdCardSignatureSession(int sessCode, String signatureId, String hash) {
    this.sessCode = sessCode;
    this.signatureId = signatureId;
    this.hash = hash;
  }

  @Override
  public String toString() {
    return sessCode + ":::" + signatureId + ":::" + hash;
  }

  public static IdCardSignatureSession fromString(String serializedIdCardSession) {
    String[] tokens = serializedIdCardSession.split(":::");
    return new IdCardSignatureSession(parseInt(tokens[0]), tokens[1], tokens[2]);
  }
}

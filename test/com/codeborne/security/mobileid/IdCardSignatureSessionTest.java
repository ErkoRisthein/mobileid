package com.codeborne.security.mobileid;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class IdCardSignatureSessionTest {

  @Test
  public void canBeSerialized() {
    IdCardSignatureSession session = new IdCardSignatureSession(123, "sigId", "hash");
    IdCardSignatureSession sessionClone = IdCardSignatureSession.fromString(session.toString());

    assertThat(sessionClone.sessCode, is(123));
    assertThat(sessionClone.signatureId, is("sigId"));
    assertThat(sessionClone.hash, is("hash"));
  }

}
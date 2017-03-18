package com.codeborne.security.mobileid;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class MobileIdSignatureSessionTest {

  @Test
  public void canBeSerialized() {
    MobileIdSignatureSession session = new MobileIdSignatureSession(123, "5555");
    MobileIdSignatureSession sessionClone = MobileIdSignatureSession.fromString(session.toString());

    assertThat(sessionClone.sessCode, is(123));
    assertThat(sessionClone.challenge, is("5555"));
  }

}
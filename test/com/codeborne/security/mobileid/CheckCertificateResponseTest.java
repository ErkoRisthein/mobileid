package com.codeborne.security.mobileid;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class CheckCertificateResponseTest {

  @Test
  public void canBeSerialized() {
    CheckCertificateResponse response = new CheckCertificateResponse("Chuck", "Norris", "666");
    CheckCertificateResponse responseClone = CheckCertificateResponse.fromString(response.toString());

    assertThat(responseClone.firstName, is("Chuck"));
    assertThat(responseClone.lastName, is("Norris"));
    assertThat(responseClone.personalCode, is("666"));
  }

}
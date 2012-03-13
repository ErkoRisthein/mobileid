package com.codeborne.security.mobileid;

import java.io.Serializable;

public class MobileIDSession implements Serializable {
    public final String firstName;
    public final String lastName;
    public final String personalCode;
    public final String challenge;
    public final int sessCode;

    public MobileIDSession(int sessCode, String challenge, String firstName, String lastName, String personalCode) {
      this.firstName = firstName;
      this.lastName = lastName;
      this.personalCode = personalCode;
      this.challenge = challenge;
      this.sessCode = sessCode;
    }
  }

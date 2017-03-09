package com.codeborne.security.mobileid;

import java.io.Serializable;

import static java.lang.Integer.parseInt;

public class MobileIDSession implements Serializable {
    public final String firstName;
    public final String lastName;
    public final String personalCode;
    public final String challenge;
    public final int sessCode;
    public final String phoneNumber;

    public MobileIDSession(int sessCode, String challenge, String firstName, String lastName, String personalCode, String phoneNumber) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.personalCode = personalCode;
        this.challenge = challenge;
        this.sessCode = sessCode;
        this.phoneNumber = phoneNumber;
    }

    public String getFullName() {
        return firstName + "\u00A0" + lastName;
    }

    @Override
    public String toString() {
        return sessCode + ":::" + challenge + ":::" + firstName + ":::" + lastName + ":::" + personalCode + ":::" + phoneNumber;
    }

    public static MobileIDSession fromString(String serializedMobileIDSession) {
        String[] tokens = serializedMobileIDSession.split(":::");
        return new MobileIDSession(parseInt(tokens[0]), tokens[1], tokens[2], tokens[3], tokens[4], tokens[5]);
    }
}

package com.codeborne.security.mobileid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MobileIDSessionTest {
    @Test
    public void canBeSerialized() {
        MobileIDSession session = new MobileIDSession(-23, "1234", "Jänis", "Põldvere-Разумовский", "38112310010", "+3725555555");

        MobileIDSession sessionClone = MobileIDSession.fromString(session.toString());
        assertEquals(-23, sessionClone.sessCode);
        assertEquals("1234", sessionClone.challenge);
        assertEquals("Jänis", sessionClone.firstName);
        assertEquals("Põldvere-Разумовский", sessionClone.lastName);
        assertEquals("38112310010", sessionClone.personalCode);
        assertEquals("+3725555555", sessionClone.phoneNumber);
    }

    @Test
    public void serializationWithEmptyValues() {
        MobileIDSession session = new MobileIDSession(0, "1234", "", "", "38112310010", "+3725555555");

        MobileIDSession sessionClone = MobileIDSession.fromString(session.toString());
        assertEquals(0, sessionClone.sessCode);
        assertEquals("1234", sessionClone.challenge);
        assertEquals("", sessionClone.firstName);
        assertEquals("", sessionClone.lastName);
        assertEquals("38112310010", sessionClone.personalCode);
        assertEquals("+3725555555", sessionClone.phoneNumber);
    }
}

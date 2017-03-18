package com.codeborne.security.mobileid;

import java.io.Serializable;

import static java.lang.Integer.parseInt;

public class MobileIdSignatureSession implements Serializable {

	private static final long serialVersionUID = -7443368341567864757L;

	public final int sessCode;

	public final String challenge;

	public MobileIdSignatureSession(int sessCode, String challenge) {
		this.sessCode = sessCode;
		this.challenge = challenge;
	}

	@Override
	public String toString() {
		return sessCode + ":::" + challenge;
	}

	public static MobileIdSignatureSession fromString(String serializedMobileIdSignatureSession) {
		String[] tokens = serializedMobileIdSignatureSession.split(":::");
		return new MobileIdSignatureSession(parseInt(tokens[0]), tokens[1]);
	}

}

package com.codeborne.security.mobileid;

public class SignatureFile {

	public final String name;
	public final String mimeType;
	public final byte[] content;

	public SignatureFile(String name, String mimeType, byte[] content) {
		this.name = name;
		this.mimeType = mimeType;
		this.content = content;
	}
}

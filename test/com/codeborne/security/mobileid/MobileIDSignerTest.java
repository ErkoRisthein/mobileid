package com.codeborne.security.mobileid;

import com.codeborne.security.digidoc.SignedDocInfo;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

public class MobileIDSignerTest {

	private static final String TEST_DIGIDOC_SERVICE_URL = "https://tsp.demo.sk.ee/";
	private MobileIDAuthenticator signer = new MobileIDAuthenticator(TEST_DIGIDOC_SERVICE_URL);

	@Before
	public void setUp() {
		System.setProperty("javax.net.ssl.trustStore", "test/keystore.jks");
	}

	@Test
	@Ignore
	public void mobileIdSignatureFlow() throws IOException {
		// startSession
		int sessCode = signer.startSession();
		assertThat(sessCode, is(not(0)));

		// createSignedDoc
		SignedDocInfo signedDocInfo = signer.createSignedDoc(sessCode);
		assertThat(signedDocInfo, is(notNullValue()));
		assertThat(signedDocInfo.getFormat(), is("BDOC"));
		assertThat(signedDocInfo.getVersion(), is("2.1"));

		// addDataFile
		String fileContent = "Test";
		byte[] fileContentBytes = fileContent.getBytes(StandardCharsets.UTF_8);
		SignatureFile file = new SignatureFile("test.txt", "text/plain", fileContentBytes);
		signedDocInfo = signer.addDataFile(sessCode, file);

		assertThat(signedDocInfo.getDataFileInfo(0), is(notNullValue()));
		assertThat(signedDocInfo.getDataFileInfo(0).getFilename(), is("test.txt"));
		assertThat(signedDocInfo.getDataFileInfo(0).getMimeType(), is("text/plain"));
		assertThat(signedDocInfo.getDataFileInfo(0).getSize(), is(4));
		assertThat(signedDocInfo.getDataFileInfo(0).getContentType(), is("EMBEDDED_BASE64"));

		// mobileSign
		String challenge = signer.mobileSign(sessCode, "38112310010", "55555555");
		assertThat(challenge, is(notNullValue()));

		// getStatusInfo
		String status = signer.getStatusInfo(sessCode);
		assertThat(status, is("SIGNATURE"));

		// getSignedDoc
		String signedDocData = signer.getSignedDoc(sessCode);
		assertThat(signedDocData, is(notNullValue()));

		byte[] bytes = Base64.getDecoder().decode(signedDocData.replaceAll("\n", "").getBytes());
		Path path = Paths.get("signedTestFile.bdoc");
		Files.write(path, bytes);

		// closeSession
		signer.closeSession(sessCode);
	}

	@Test
	@Ignore
	public void compactMobileIdSignatureFlow() throws Exception {
		List<SignatureFile> files = asList(
			new SignatureFile("test1.txt", "text/plain", "Test1".getBytes()),
			new SignatureFile("test2.txt", "text/plain", "Test2".getBytes())
		);

		MobileIdSignatureSession session = signer.startSign(files, "38112310010", "55555555");

		byte[] signedFile = signer.getSignedFile(session);
		assertThat(signedFile, is(notNullValue()));
	}
}

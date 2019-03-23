package com.codeborne.security.mobileid;

import com.codeborne.security.AuthenticationException;
import com.codeborne.security.digidoc.DigiDocServicePortType;
import com.codeborne.security.digidoc.DigiDocService_Service;
import com.codeborne.security.digidoc.DigiDocService_ServiceLocator;
import com.codeborne.security.digidoc.SignedDocInfo;
import com.codeborne.security.digidoc.holders.SignedDocInfoHolder;

import javax.xml.rpc.ServiceException;
import javax.xml.rpc.holders.IntHolder;
import javax.xml.rpc.holders.StringHolder;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.Base64;
import java.util.List;

import static com.codeborne.security.AuthenticationException.Code.valueOf;

/**
 * Authenticates with Mobile-ID.<br>
 * Can be used as a preconfigured singleton (eg Spring bean).<br>
 * <p>Use {@link #startLogin} to initiate the login session and display challenge to the user,
 * then {@link #waitForLogin(MobileIDSession)} to wait for the authentication to complete.</p>
 * <p>Various setters can be used to configure the behaviour.</p>
 */
public class MobileIDAuthenticator {
  private String language = "EST";
  private String country = "EE";
  private String serviceName = "Testimine";
  private String loginMessage = "";
  private int retryCount = 60;
  private int pollIntervalMs = 3000;
  private final String messagingMode = "asynchClientServer";

  DigiDocServicePortType service;

  public MobileIDAuthenticator() {
  }

  public MobileIDAuthenticator(String digidocServiceURL) {
    setDigidocServiceURL(digidocServiceURL);
  }

  public MobileIDAuthenticator(String digidocServiceURL, String serviceName) {
    setDigidocServiceURL(digidocServiceURL);
    this.serviceName = serviceName;
  }

  public MobileIDAuthenticator(URL digidocServiceURL) {
    setDigidocServiceURL(digidocServiceURL);
  }

  public MobileIDAuthenticator(URL digidocServiceURL, String serviceName) {
    setDigidocServiceURL(digidocServiceURL);
    this.serviceName = serviceName;
  }

  public final MobileIDAuthenticator setDigidocServiceURL(String digidocServiceURL) {
    try {
      return setDigidocServiceURL(new URL(digidocServiceURL));
    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }
  }

  public final MobileIDAuthenticator setDigidocServiceURL(URL digidocServiceURL) {
    DigiDocService_Service digiDocService = new DigiDocService_ServiceLocator();
    try {
      service = digiDocService.getDigiDocService(digidocServiceURL);
    }
    catch (ServiceException e) {
      throw new RuntimeException("Failed to initialize Mobile-ID support", e);
    }
    return this;
  }

  public void setLanguage(String language) {
    this.language = language;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public void setServiceName(String serviceName) {
    this.serviceName = serviceName;
  }

  public void setLoginMessage(String loginMessage) {
    this.loginMessage = loginMessage;
  }

  public void setRetryCount(int retryCount) {
    this.retryCount = retryCount;
  }

  public void setPollIntervalMs(int pollIntervalMs) {
    this.pollIntervalMs = pollIntervalMs;
  }

  /**
   * Initiates the login session. Note: returned session already contains user's info, but the authenticity is not yet verified.
   *
   * @param personalCode user's personal code
   * @param countryCode  two letter country code, eg EE
   * @throws AuthenticationException is authentication unsuccessful
   * @return MobileIDSession instance containing CHALLENGE ID that should be shown to the user
   */
  public MobileIDSession startLogin(String personalCode, String countryCode) {
    return startLogin(personalCode, countryCode, null);
  }

  /**
   * Initiates the login session. Note: returned session already contains user's info, but the authenticity is not yet verified.
   *
   * @param phone phone number <b>with country code</b> (eg "+37255667788" or "37255667788").
   * @throws AuthenticationException is authentication unsuccessful
   * @return MobileIDSession instance containing CHALLENGE ID that should be shown to the user
   */
  public MobileIDSession startLogin(String phone) {
    return startLogin(null, null, phone);
  }

  protected MobileIDSession startLogin(String personalCode, String countryCode, String phone) {
    validateServiceUrl();

    IntHolder sessCode = new IntHolder();
    StringHolder result = new StringHolder();
    StringHolder firstName = new StringHolder();
    StringHolder lastName = new StringHolder();
    StringHolder personalCodeHolder = new StringHolder();
    StringHolder challenge = new StringHolder();

    try {
      service.mobileAuthenticate(personalCode, countryCode, normalizePhoneNumber(phone), language, serviceName, loginMessage, generateSPChallenge(),
              messagingMode, 0, false, false, sessCode, result,
              personalCodeHolder, firstName, lastName, new StringHolder(), new StringHolder(), new StringHolder(), challenge,
              new StringHolder(), new StringHolder());
    }
    catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return new MobileIDSession(sessCode.value, challenge.value, firstName.value, lastName.value, personalCodeHolder.value, phone);
  }

  private void validateServiceUrl() {
    if (service == null) {
      throw new IllegalStateException("digidocServiceURL is not initialized");
    }
  }

  String normalizePhoneNumber(String phone) {
    return phone != null && phone.startsWith("+") ? phone.substring(1) : phone;
  }

  private void validateOkResult(StringHolder result) {
    if (!"OK".equals(result.value))
      throw new AuthenticationException(valueOf(result.value));
  }

  private void validateGoodResult(StringHolder result) {
    if (!"GOOD".equals(result.value))
      throw new AuthenticationException(valueOf(result.value));
  }

  protected String generateSPChallenge() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 20; i++) sb.append((int) (Math.random() * 10));
    return sb.toString();
  }

  /**
   * Waits until user confirms their identity using the mobile device.
   * <p>This is a blocking version of {@link #isLoginComplete(MobileIDSession)}
   *
   * @param session previously returned by {@link #startLogin}
   * @throws AuthenticationException is authentication unsuccessful
   * @return MobileIDSession instance containing user name and personal code
   */
  public MobileIDSession waitForLogin(MobileIDSession session) {
    int tryCount = 0;
    while (sleep(pollIntervalMs) && !isLoginComplete(session) && tryCount < retryCount) {
        tryCount++;
    }
    if (tryCount >= retryCount)
      throw new AuthenticationException(valueOf(getLoginStatus(session).value));
    return session;
  }

  /**
   * Checks whether login is already complete.
   * <p>This is a non-blocking version of {@link #waitForLogin(MobileIDSession)}
   *
   * @param session previously returned by {@link #startLogin}
   * @return true if login successful
   */
  public boolean isLoginComplete(MobileIDSession session) {
    StringHolder status = getLoginStatus(session);
    if ("OUTSTANDING_TRANSACTION".equals(status.value))
      return false;
    else if ("USER_AUTHENTICATED".equals(status.value))
      return true;
    else
      throw new AuthenticationException(valueOf(status.value));
  }

  private StringHolder getLoginStatus(MobileIDSession session) {
    StringHolder status = new StringHolder("OUTSTANDING_TRANSACTION");
    try {
      service.getMobileAuthenticateStatus(session.sessCode, false, status, new StringHolder());
    }
    catch (RemoteException e) {
      throw new AuthenticationException(e);
    }
    return status;
  }

  boolean sleep(int sleepTimeMilliseconds) {
    try {
      Thread.sleep(sleepTimeMilliseconds);
      return true;
    }
    catch (InterruptedException e) {
      return false;
    }
  }

  /**
   * @param files a List of SignatureFile(fileName, mimeType, contentAsBytes) instances
   * @param personalCode the personal code of the user
   * @param phone the phone number of the user
   * @return MobileIdSignatureSession instance that contains the session code and the challenge that should be shown to the user
   */
  public MobileIdSignatureSession startSign(List<SignatureFile> files, String personalCode, String phone) {
    final int sessCode = startSession();
    createSignedDoc(sessCode);
    files.forEach(file -> addDataFile(sessCode, file));
    String challenge = mobileSign(sessCode, personalCode, phone);
    return new MobileIdSignatureSession(sessCode, challenge);
  }

  /**
   * @param session MobileIdSignatureSession previously returned by {@link #startSign(List, String, String)}
   * @return byte array of the bdoc file content or null if the signing process is not finished yet
   */
  public byte[] getSignedFile(MobileIdSignatureSession session) {
    String status = getStatusInfo(session.sessCode);
    if ("OUTSTANDING_TRANSACTION".equals(status)) {
      return null;
    } else if ("SIGNATURE".equals(status)) {
      String signedDoc = getSignedDoc(session.sessCode);
      closeSession(session.sessCode);
      return toBytes(signedDoc);
    } else {
      throw new AuthenticationException(valueOf(status));
    }
  }

  private byte[] toBytes(String base64) {
    return Base64.getDecoder().decode(base64.replaceAll("\n", "").getBytes());
  }

  int startSession() {
    validateServiceUrl();

    IntHolder sessCode = new IntHolder();
    StringHolder result = new StringHolder();
    SignedDocInfoHolder signedDocInfo = new SignedDocInfoHolder();

    try {
      service.startSession(null, null, true, null, result, sessCode, signedDocInfo);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return sessCode.value;
  }

  SignedDocInfo createSignedDoc(int sessCode) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    SignedDocInfoHolder signedDocInfo = new SignedDocInfoHolder();

    try {
      service.createSignedDoc(sessCode, "BDOC", "2.1", result, signedDocInfo);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return signedDocInfo.value;
  }

  SignedDocInfo addDataFile(int sessCode, SignatureFile file) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    SignedDocInfoHolder signedDocInfo = new SignedDocInfoHolder();
    String base64FileContent =  new String(Base64.getEncoder().encode(file.content));

    try {
      service.addDataFile(sessCode, file.name, file.mimeType, "EMBEDDED_BASE64", file.content.length, null, null, base64FileContent, result, signedDocInfo);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return signedDocInfo.value;
  }

  String mobileSign(int sessCode, String personalCode, String phone) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    StringHolder statusCode = new StringHolder();
    StringHolder challenge = new StringHolder();

    try {
      service.mobileSign(sessCode, personalCode, country, normalizePhoneNumber(phone), serviceName, null, language,
              null, null, null, null, null, null, messagingMode, 0, true, true, result, statusCode, challenge);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return challenge.value;
  }

  String getStatusInfo(int sessCode) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    StringHolder statusCode = new StringHolder();

    try {
      service.getStatusInfo(sessCode, true, false, result, statusCode, new SignedDocInfoHolder());
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return statusCode.value;
  }

  String getSignedDoc(int sessCode) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    StringHolder signedDocData = new StringHolder();

    try {
      service.getSignedDoc(sessCode, result, signedDocData);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return signedDocData.value;
  }

  void closeSession(int sessCode) {
    validateServiceUrl();

    try {
      service.closeSession(sessCode);
    } catch (RemoteException e) {
      throw new AuthenticationException(e);
    }
  }

  /**
   * @param certificate Certificate to be checked for validity, in Base64 format. May include
   *                    "---BEGIN CERTIFICATE---" and "---END CERTIFICATE---" lines (according to PEM format)
   * @return CheckCertificateResponse that contains the firstName, lastName and personalCode
   */
  public CheckCertificateResponse checkCertificate(String certificate) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    StringHolder firstName = new StringHolder();
    StringHolder lastName = new StringHolder();
    StringHolder personalCode = new StringHolder();

    try {
      service.checkCertificate(certificate, false, result, personalCode, firstName, lastName, new StringHolder(),
        new StringHolder(), new StringHolder(), new StringHolder(), new StringHolder(), new StringHolder(), new StringHolder());
    }
    catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateGoodResult(result);

    return new CheckCertificateResponse(firstName.value, lastName.value, personalCode.value);
  }

  /**
   * @param files a List of SignatureFile(fileName, mimeType, contentAsBytes) instances
   * @param signingCertificate the PIN2 certificate that is used for digital signature
   * @return IdCardSignatureSession instance that contains the session code, signatureId
   * and the hash that has to be signed by the client
   */
  public IdCardSignatureSession startSign(List<SignatureFile> files, String signingCertificate) {
    final int sessCode = startSession();
    createSignedDoc(sessCode);
    files.forEach(file -> addDataFile(sessCode, file));

    return prepareSignature(sessCode, signingCertificate);
  }

  /**
   * @param session IdCardSignatureSession previously returned by {@link #startSign(List, String)}
   * @param signedHash the hash that was signed by the client using PIN2
   * @return byte array of the bdoc file content
   */
  public byte[] getSignedFile(IdCardSignatureSession session, String signedHash) {
    finalizeSignature(session, signedHash);
    String signedDoc = getSignedDoc(session.sessCode);
    closeSession(session.sessCode);
    return toBytes(signedDoc);
  }

  IdCardSignatureSession prepareSignature(int sessCode, String signingCertificate) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    StringHolder signatureId = new StringHolder();
    StringHolder hash = new StringHolder();

    try {
      service.prepareSignature(sessCode, signingCertificate, null, null, null, null, null, null, null,
        result, signatureId, hash);
    }
    catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return new IdCardSignatureSession(sessCode, signatureId.value, hash.value);
  }

  SignedDocInfo finalizeSignature(IdCardSignatureSession session, String signedHash) {
    validateServiceUrl();

    StringHolder result = new StringHolder();
    SignedDocInfoHolder signedDocInfo = new SignedDocInfoHolder();

    try {
      service.finalizeSignature(session.sessCode, session.signatureId, signedHash, result, signedDocInfo);
    }
    catch (RemoteException e) {
      throw new AuthenticationException(e);
    }

    validateOkResult(result);

    return signedDocInfo.value;
  }
}

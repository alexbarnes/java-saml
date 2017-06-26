package com.onelogin.saml2.settings;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Util;

/**
 * SettingsBuilder class of OneLogin's Java Toolkit.
 *
 * A class that implements the settings builder
 */
public class SettingsBuilder {

  /**
   * Private property to construct a logger for this class.
   */
  private static final Logger LOGGER = LoggerFactory.getLogger(SettingsBuilder.class);

	/**
     * Private property that contains the SAML settings
     */
	private Properties prop = new Properties();

	private String idpMetadata;

	/**
     * Saml2Settings object
     */
	private Saml2Settings saml2Setting;

	private boolean strict = false;
  private boolean debug = false;

  // SP
  private String spEntityId;
  private String acsUrl;
  private String acsUrlBinding;
  private String spSloURL;
  private String spSloBinding;
  private String nameIdFormat;

  private String spX509Cert;
  private String spPrivateKey;

  // IDP
  private String idpEntityId;
  private String ssoServiceUrl;
  private String ssoBinding;
  private String idpSloUrl;
  private String idpSloResponseUrl;
  private String idpSloBinding;

  private String idpX509Cert;
  private String idpCertFingerprint;
  private String idpCertFingerPrintAlgorithm;

  // Security
  Boolean nameIdEncrypted;
  Boolean authnRequestsSigned;
  Boolean logoutRequestSigned;
  Boolean logoutResponseSigned;
  Boolean wantMessagesSigned;
  Boolean wantAssertionsSigned;
  Boolean wantAssertionsEncrypted;
  Boolean wantNameId;
  Boolean wantNameIdEncrypted;
  Boolean wantXMLValidation;
  Boolean signMetadata;
  List<String> requestedAuthnContext;
  String requestedAuthnContextComparison;
  String signatureAlgorithm;
  Boolean rejectUnsolicitedResponsesWithInResponseTo;

  // Compression
  Boolean compressRequest;
  Boolean compressResponse;

  private final List<Contact> contacts = new ArrayList<>();
  private Organization organization;

	/**
	 * Load settings from the file
	 *
	 * @param propFileName
	 *            OneLogin_Saml2_Settings
	 *
	 * @return the SettingsBuilder object with the settings loaded from the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	public SettingsBuilder fromFile(String propFileName) throws IOException, Error {
		this.loadPropFile(propFileName);
		return this;
	}


	/**
   * Load metadata from the file
   *
   * @param propFileName
   *            OneLogin_Saml2_Settings
   *
   * @return the SettingsBuilder object with the settings loaded from the file
   *
   * @throws IOException
   * @throws Error
   */
  public SettingsBuilder fromIdpMetadata(String idpMetadataLocation) throws IOException, Error {
    this.idpMetadata = Util.getAbsoluteFileAsString(idpMetadataLocation);
    return this;
  }

	/**
	 * Loads the settings from the properties file
	 *
	 * @param propFileName
	 *            the name of the file
	 *
	 * @throws IOException
	 * @throws Error
	 */
	private void loadPropFile(String propFileName) throws IOException, Error {

		InputStream inputStream = null;

		try {
			inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);
			if (inputStream != null) {
				this.prop.load(inputStream);
				LOGGER.debug("properties file " + propFileName + "loaded succesfully");
			} else {
				String errorMsg = "properties file '" + propFileName + "' not found in the classpath";
				LOGGER.error(errorMsg);
				throw new Error(errorMsg, Error.SETTINGS_FILE_NOT_FOUND);
			}
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}
			} catch (IOException e) {
				LOGGER.warn("properties file '"  + propFileName +  "' not closed properly.");
			}
		}
	}

	/**
	 * Loads the settings from a properties object
	 *
	 * @param prop
	 *            contains the properties
	 *
	 * @return the SettingsBuilder object with the settings loaded from the prop object
	 */
	public SettingsBuilder fromProperties(Properties prop) {
	    this.prop = prop;
	    return this;
	}

	public SettingsBuilder withIdpEntityId(String idpEntityId) {
    this.idpEntityId = idpEntityId;
    return this;
  }

  public SettingsBuilder strict() {
    this.strict = true;
    return this;
  }

  public SettingsBuilder debug() {
    this.debug = true;
    return this;
  }

  public SettingsBuilder withOrganization(String name, String displayName, String url) {
    this.organization = new Organization(name, displayName, url);
    return this;
  }

  public SettingsBuilder withTechnicalContact(String name, String email) {
    contacts.add(new Contact("technical", name, email));
    return this;
  }

  public SettingsBuilder withSupportContact(String name, String email) {
    contacts.add(new Contact("support", name, email));
    return this;
  }

  public SettingsBuilder withSpEntityId(String spEntityId) {
    this.spEntityId = spEntityId;
    return this;
  }

  public SettingsBuilder withAcsUrl(String acsUrl) {
    this.acsUrl = acsUrl;
    return this;
  }

  /**
   * Build the {@linkplain Saml2Settings} applying settings in the following order:
   * <ol>
   *  <li>A properties file or properties</li>
   *  <li>A SAML IdP metadata configuration file</li>
   *  <li>Any specifically set properties using chained builder methods</li>
   *  </ol>
   *
   * @return the settings to be used for SAML actions.
   */
	public Saml2Settings build() {

		saml2Setting = new Saml2Settings();

		// Load basic settings from an Idp metadata file if supplied
		if (StringUtils.isNotEmpty(idpMetadata)) {
		  IdPMetadataParser.parse(saml2Setting, idpMetadata);
		}

		// Then add in any properties file settings
		if (prop != null) {
		  PropertiesFileParser.parse(saml2Setting, prop);
		}

		// Finally any specific overrides set on this builder directly. These
		// will replace settings obtained from properties files or metadata.
		saml2Setting.setStrict(strict);
		saml2Setting.setDebug(debug);

		setIdpSettings(saml2Setting);
		setSPSettings(saml2Setting);
		setSecuritySettings(saml2Setting);

		if (compressRequest != null)
		  saml2Setting.setCompressRequest(compressRequest);

		if (compressResponse != null)
      saml2Setting.setCompressRequest(compressResponse);

		// Add any contacts we have set on the builder to those
		// which we obtained from properties or metadata.
		if (!contacts.isEmpty())
		  saml2Setting.getContacts().addAll(contacts);

		if (organization != null)
		  saml2Setting.setOrganization(organization);

		return saml2Setting;
	}


	private void setIdpSettings(Saml2Settings saml2Setting) {
    if (StringUtils.isNotEmpty(idpEntityId))
      saml2Setting.setIdpEntityId(idpEntityId);

    if (StringUtils.isNotEmpty(ssoServiceUrl))
      saml2Setting.setIdpSingleSignOnServiceUrl(Util.createUrl(ssoServiceUrl));

    if (StringUtils.isNotEmpty(ssoBinding))
      saml2Setting.setIdpSingleSignOnServiceBinding(ssoBinding);

    if (StringUtils.isNotEmpty(idpSloUrl))
      saml2Setting.setIdpSingleLogoutServiceUrl(Util.createUrl(idpSloUrl));

    if (StringUtils.isNotEmpty(idpSloResponseUrl))
      saml2Setting.setIdpSingleLogoutServiceResponseUrl(Util.createUrl(idpSloResponseUrl));

    if (StringUtils.isNotEmpty(idpSloBinding))
      saml2Setting.setIdpSingleLogoutServiceBinding(idpSloBinding);

    if (StringUtils.isNotEmpty(idpX509Cert))
      saml2Setting.setIdpx509cert(Util.createCertificate(idpX509Cert));

    if (StringUtils.isNotEmpty(idpCertFingerprint))
      saml2Setting.setIdpCertFingerprint(idpCertFingerprint);

    if (StringUtils.isNotEmpty(idpCertFingerPrintAlgorithm))
      saml2Setting.setIdpCertFingerprintAlgorithm(idpCertFingerPrintAlgorithm);
  }


	private void setSPSettings(Saml2Settings saml2Setting) {
	  if (StringUtils.isNotEmpty(spEntityId))
      saml2Setting.setSpEntityId(spEntityId);

	  if (StringUtils.isNotEmpty(acsUrl))
      saml2Setting.setSpAssertionConsumerServiceUrl(Util.createUrl(acsUrl));

	  if (StringUtils.isNotEmpty(acsUrlBinding))
      saml2Setting.setSpAssertionConsumerServiceBinding(acsUrlBinding);

	  if (StringUtils.isNotEmpty(spSloURL))
      saml2Setting.setSpSingleLogoutServiceUrl(Util.createUrl(spSloURL));

	  if (StringUtils.isNotEmpty(spSloBinding))
      saml2Setting.setSpSingleLogoutServiceBinding(spSloBinding);

	  if (StringUtils.isNotEmpty(nameIdFormat))
      saml2Setting.setSpNameIDFormat(nameIdFormat);

	  if (StringUtils.isNotEmpty(spX509Cert))
      saml2Setting.setSpX509cert(Util.createCertificate(spX509Cert));

	  if (StringUtils.isNotEmpty(spPrivateKey))
      saml2Setting.setSpPrivateKey(Util.createPrivateKey(spPrivateKey));
	}

	private void setSecuritySettings(Saml2Settings saml2Setting) {
    if (nameIdEncrypted != null)
      saml2Setting.setNameIdEncrypted(nameIdEncrypted);

    if (authnRequestsSigned != null)
      saml2Setting.setAuthnRequestsSigned(authnRequestsSigned);

    if (logoutRequestSigned != null)
      saml2Setting.setLogoutRequestSigned(logoutRequestSigned);

    if (logoutResponseSigned != null)
      saml2Setting.setLogoutResponseSigned(logoutResponseSigned);

    if (wantMessagesSigned != null)
      saml2Setting.setWantMessagesSigned(wantMessagesSigned);

    if (wantAssertionsSigned != null)
      saml2Setting.setWantAssertionsSigned(wantAssertionsSigned);

    if (wantAssertionsEncrypted != null)
      saml2Setting.setWantAssertionsEncrypted(wantAssertionsEncrypted);

    if (wantNameId != null)
      saml2Setting.setWantNameId(wantNameId);

    if (wantNameIdEncrypted != null)
      saml2Setting.setWantNameIdEncrypted(wantNameIdEncrypted);

    if (wantXMLValidation != null)
      saml2Setting.setWantXMLValidation(wantXMLValidation);

    if (signMetadata != null)
      saml2Setting.setSignMetadata(signMetadata);

    if (!requestedAuthnContext.isEmpty())
      saml2Setting.getRequestedAuthnContext().addAll(requestedAuthnContext);

    if (StringUtils.isNotEmpty(requestedAuthnContextComparison))
      saml2Setting.setRequestedAuthnContextComparison(requestedAuthnContextComparison);

    if (StringUtils.isNotEmpty(signatureAlgorithm))
      saml2Setting.setSignatureAlgorithm(signatureAlgorithm);

    if (rejectUnsolicitedResponsesWithInResponseTo != null)
      saml2Setting.setRejectUnsolicitedResponsesWithInResponseTo(rejectUnsolicitedResponsesWithInResponseTo);
  }


	/**
	 * Loads a property of the type X509Certificate from file
	 *
	 * @param filename
	 *            the file name of the file that contains the X509Certificate
	 *
	 * @return the X509Certificate object
	 */
	/*
	protected X509Certificate loadCertificateFromFile(String filename) {
		String certString = null;

		try {
			certString = Util.getFileAsString(filename.trim());
		} catch (URISyntaxException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		}
		catch (IOException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		}

		try {
			return Util.loadCert(certString);
		} catch (CertificateException e) {
			LOGGER.error("Error loading certificate from file.", e);
			return null;
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("the certificate is not in correct format.", e);
			return null;
		}
	}
	*/


	/**
	 * Loads a property of the type PrivateKey from file
	 *
	 * @param filename
	 *            the file name of the file that contains the PrivateKey
	 *
	 * @return the PrivateKey object
	 */
	/*
	protected PrivateKey loadPrivateKeyFromFile(String filename) {
		String keyString = null;

		try {
			keyString = Util.getFileAsString(filename.trim());
		} catch (URISyntaxException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		} catch (IOException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		}

		try {
			return Util.loadPrivateKey(keyString);
		} catch (GeneralSecurityException e) {
			LOGGER.error("Error loading privatekey from file.", e);
			return null;
		} catch (IOException e) {
			LOGGER.debug("Error loading privatekey from file.", e);
			return null;
		}
	}
	*/
}

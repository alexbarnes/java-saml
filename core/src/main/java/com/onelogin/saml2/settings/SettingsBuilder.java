package com.onelogin.saml2.settings;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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

	private Boolean strict;
  private Boolean debug;

  // SP
  private String spEntityId;
  private String acsUrl;
  private String acsUrlBinding;
  private URL spSloURL;
  private String spSloBinding;
  private String nameIdFormat;

  private X509Certificate spX509Cert;
  private PrivateKey spPrivateKey;

  // IDP
  private String idpEntityId;
  private URL ssoServiceUrl;
  private String ssoBinding;
  private URL idpSloUrl;
  private URL idpSloResponseUrl;
  private String idpSloBinding;

  private X509Certificate idpX509Cert;
  private String idpCertFingerprint;
  private String idpCertFingerPrintAlgorithm;

  // Security
  private Boolean nameIdEncrypted;
  private Boolean authnRequestsSigned;
  private Boolean logoutRequestSigned;
  private Boolean logoutResponseSigned;
  private Boolean wantMessagesSigned;
  private Boolean wantAssertionsSigned;
  private Boolean wantAssertionsEncrypted;
  private Boolean wantNameId;
  private Boolean wantNameIdEncrypted;
  private Boolean wantXMLValidation;
  private Boolean signMetadata;
  private List<String> requestedAuthnContext = new ArrayList<>();
  private String requestedAuthnContextComparison;
  private String signatureAlgorithm;
  private Boolean rejectUnsolicitedResponsesWithInResponseTo;

  // Compression
  private Boolean compressRequest;
  private Boolean compressResponse;

  private List<Contact> contacts = new ArrayList<>();
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
  public SettingsBuilder fromIdpMetadata(String idpMetadataLocation) {
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



	/**
	 * Loads the settings from an existing {@linkplain Saml2Settings} object.
	 *
	 * @param settings the settings to copy from
	 * @return the SettingsBuilder object with the settings loaded from the existing settings object
	 */
	public SettingsBuilder fromExistingSettings(Saml2Settings settings) {
	  this.strict = settings.isStrict();
	  this.debug = settings.isDebugActive();

	  // SP
	  this.spEntityId = settings.getSpEntityId();
	  this.acsUrl = settings.getSpAssertionConsumerServiceUrl().toExternalForm();
	  this.acsUrlBinding = settings.getSpAssertionConsumerServiceBinding();
	  this.spSloURL = settings.getSpSingleLogoutServiceUrl();
	  this.spSloBinding = settings.getSpSingleLogoutServiceBinding();
	  this.nameIdFormat = settings.getSpNameIDFormat();
	  this.spX509Cert = settings.getSPcert();
	  this.spPrivateKey = settings.getSPkey();

	  // IDP
	  this.idpEntityId = settings.getIdpEntityId();
	  this.ssoServiceUrl = settings.getIdpSingleSignOnServiceUrl();
	  this.ssoBinding = settings.getIdpSingleSignOnServiceBinding();
	  this.idpSloUrl = settings.getIdpSingleLogoutServiceUrl();
	  this.idpSloResponseUrl = settings.getIdpSingleLogoutServiceResponseUrl();
	  this.idpSloBinding = settings.getIdpSingleLogoutServiceBinding();

	  this.idpX509Cert = settings.getIdpx509cert();
	  this.idpCertFingerprint = settings.getIdpCertFingerprint();
	  this.idpCertFingerPrintAlgorithm = settings.getIdpCertFingerprintAlgorithm();

	  this.nameIdEncrypted = settings.getNameIdEncrypted();
	  this.authnRequestsSigned = settings.getAuthnRequestsSigned();
	  this.logoutRequestSigned = settings.getLogoutRequestSigned();
	  this.logoutResponseSigned = settings.getLogoutResponseSigned();
	  this.wantMessagesSigned = settings.getWantMessagesSigned();
	  this.wantAssertionsSigned = settings.getWantAssertionsSigned();
	  this.wantAssertionsEncrypted = settings.getWantAssertionsEncrypted();
	  this.wantNameId = settings.getWantNameId();
	  this.wantNameIdEncrypted = settings.getWantNameIdEncrypted();
	  this.wantXMLValidation = settings.getWantXMLValidation();
	  this.signMetadata = settings.getSignMetadata();
	  this.requestedAuthnContext = settings.getRequestedAuthnContext();
	  this.requestedAuthnContextComparison = settings.getRequestedAuthnContextComparison();
	  this.signatureAlgorithm = settings.getSignatureAlgorithm();
	  this.rejectUnsolicitedResponsesWithInResponseTo = settings.isRejectUnsolicitedResponsesWithInResponseTo();
	  this.compressRequest = settings.isCompressRequestEnabled();
	  this.compressResponse = settings.isCompressResponseEnabled();
	  this.contacts = settings.getContacts();
	  this.organization = settings.getOrganization();
	  return this;
	}

	// SP chained builder methods
  public SettingsBuilder withSpEntityId(String spEntityId) {
    this.spEntityId = spEntityId;
    return this;
  }

  public SettingsBuilder withAcsUrl(String acsUrl) {
    this.acsUrl = acsUrl;
    return this;
  }

  public SettingsBuilder withAcsUrlBinding(String acsUrlBinding) {
    this.acsUrlBinding = acsUrlBinding;
    return this;
  }

  public SettingsBuilder withSpSloURL(String spSloURL) {
    this.spSloURL = Util.createUrl(spSloURL);
    return this;
  }

  public SettingsBuilder withSpSloBinding(String spSloBinding) {
    this.spSloBinding = spSloBinding;
    return this;
  }

  public SettingsBuilder withNameIdFormat(String nameIdFormat) {
    this.nameIdFormat = nameIdFormat;
    return this;
  }

  public SettingsBuilder withSpx509Certificate(String cert) {
    this.spX509Cert = Util.createCertificate(cert);
    return this;
  }

  public SettingsBuilder withSpPrivateKey(String key) {
    this.spPrivateKey = Util.createPrivateKey(key);
    return this;
  }

  // Idp chained builder methods.
	public SettingsBuilder withIdpEntityId(String idpEntityId) {
    this.idpEntityId = idpEntityId;
    return this;
  }

	public SettingsBuilder withSsoBinding(String ssoBinding) {
    this.ssoBinding = ssoBinding;
    return this;
  }

	public SettingsBuilder withIdpSloUrl(String idpSloUrl) {
    this.idpSloUrl = Util.createUrl(idpSloUrl);
    return this;
  }

	public SettingsBuilder withIdpSloResponseUrl(String idpSloResponseUrl) {
    this.idpSloResponseUrl = Util.createUrl(idpSloResponseUrl);
    return this;
  }

	public SettingsBuilder withIdpSloBinding(String idpSloBinding) {
    this.idpSloBinding = idpSloBinding;
    return this;
  }

	public SettingsBuilder withIdpX509Cert(String idpX509Cert) {
    this.idpX509Cert = Util.createCertificate(idpX509Cert);
    return this;
  }

	public SettingsBuilder withIdpCertFingerprint(String idpCertFingerprint) {
    this.idpCertFingerprint = idpCertFingerprint;
    return this;
  }

	public SettingsBuilder withIdpCertFingerPrintAlgorithm(String idpCertFingerPrintAlgorithm) {
    this.idpCertFingerPrintAlgorithm = idpCertFingerPrintAlgorithm;
    return this;
  }

	// Security chained builder methods.
	public SettingsBuilder nameIdEncrypted() {
    this.nameIdEncrypted = true;
    return this;
  }

	public SettingsBuilder authnRequestsSigned() {
    this.authnRequestsSigned = true;
    return this;
  }

	public SettingsBuilder logoutRequestSigned() {
    this.logoutRequestSigned = true;
    return this;
  }

	public SettingsBuilder logoutResponseSigned() {
    this.logoutResponseSigned = true;
    return this;
  }

	public SettingsBuilder wantMessagesSigned() {
    this.wantMessagesSigned = true;
    return this;
  }

	public SettingsBuilder wantAssertionsSigned() {
    this.wantAssertionsSigned = true;
    return this;
  }

	public SettingsBuilder wantAssertionsEncrypted() {
    this.wantAssertionsEncrypted = true;
    return this;
  }

	public SettingsBuilder wantNameId() {
    this.wantNameId = true;
    return this;
  }

	public SettingsBuilder wantNameIdEncrypted() {
    this.wantNameIdEncrypted = true;
    return this;
  }

	public SettingsBuilder wantXMLValidation() {
    this.wantXMLValidation = true;
    return this;
  }

	public SettingsBuilder signMetadata() {
    this.signMetadata = true;
    return this;
  }

	public SettingsBuilder rejectUnsolicitedResponsesWithInResponseTo() {
    this.rejectUnsolicitedResponsesWithInResponseTo = true;
    return this;
  }

	public SettingsBuilder withRequestedAuthnContextComparison(String requestedAuthnContextComparison) {
    this.requestedAuthnContextComparison = requestedAuthnContextComparison;
    return this;
  }

	public SettingsBuilder withSignatureAlgorithm(String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
    return this;
  }

	public SettingsBuilder addRequestedAuthnContext(String requestedAuthnContext) {
    this.requestedAuthnContext.add(requestedAuthnContext);
    return this;
  }


	// Misc chained builder methods
  public SettingsBuilder strict() {
    this.strict = true;
    return this;
  }

  public SettingsBuilder debug() {
    this.debug = true;
    return this;
  }

  public SettingsBuilder compressRequest() {
    this.compressRequest = true;
    return this;
  }

  public SettingsBuilder compressResponse() {
    this.compressResponse = true;
    return this;
  }

  // Organization and contacts
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
		if (strict != null)
		  saml2Setting.setStrict(strict);

		if (debug != null)
		  saml2Setting.setDebug(debug);

		if (compressRequest != null)
		  saml2Setting.setCompressRequest(compressRequest);

		if (compressResponse != null)
      saml2Setting.setCompressRequest(compressResponse);


    setIdpSettings(saml2Setting);
    setSPSettings(saml2Setting);
    setSecuritySettings(saml2Setting);

		// Add any contacts we have set on the builder to those
		// which we obtained from properties or metadata.
		if (!contacts.isEmpty())
		  saml2Setting.getContacts().addAll(contacts);

		if (organization != null)
		  saml2Setting.setOrganization(organization);

		return saml2Setting;
	}


	/**
	 * @param saml2Setting
	 */
	private void setIdpSettings(Saml2Settings saml2Setting) {
    if (StringUtils.isNotEmpty(idpEntityId))
      saml2Setting.setIdpEntityId(idpEntityId);

    if (ssoServiceUrl != null)
      saml2Setting.setIdpSingleSignOnServiceUrl(ssoServiceUrl);

    if (StringUtils.isNotEmpty(ssoBinding))
      saml2Setting.setIdpSingleSignOnServiceBinding(ssoBinding);

    if (idpSloUrl != null)
      saml2Setting.setIdpSingleLogoutServiceUrl(idpSloUrl);

    if (idpSloResponseUrl != null)
      saml2Setting.setIdpSingleLogoutServiceResponseUrl(idpSloResponseUrl);

    if (StringUtils.isNotEmpty(idpSloBinding))
      saml2Setting.setIdpSingleLogoutServiceBinding(idpSloBinding);

    if (idpX509Cert != null)
      saml2Setting.setIdpx509cert(idpX509Cert);

    if (StringUtils.isNotEmpty(idpCertFingerprint))
      saml2Setting.setIdpCertFingerprint(idpCertFingerprint);

    if (StringUtils.isNotEmpty(idpCertFingerPrintAlgorithm))
      saml2Setting.setIdpCertFingerprintAlgorithm(idpCertFingerPrintAlgorithm);
  }


	/**
	 * @param saml2Setting
	 */
	private void setSPSettings(Saml2Settings saml2Setting) {
	  if (StringUtils.isNotEmpty(spEntityId))
      saml2Setting.setSpEntityId(spEntityId);

	  if (StringUtils.isNotEmpty(acsUrl))
      saml2Setting.setSpAssertionConsumerServiceUrl(Util.createUrl(acsUrl));

	  if (StringUtils.isNotEmpty(acsUrlBinding))
      saml2Setting.setSpAssertionConsumerServiceBinding(acsUrlBinding);

	  if (spSloURL != null)
      saml2Setting.setSpSingleLogoutServiceUrl(spSloURL);

	  if (StringUtils.isNotEmpty(spSloBinding))
      saml2Setting.setSpSingleLogoutServiceBinding(spSloBinding);

	  if (StringUtils.isNotEmpty(nameIdFormat))
      saml2Setting.setSpNameIDFormat(nameIdFormat);

	  if (spX509Cert != null)
      saml2Setting.setSpX509cert(spX509Cert);

	  if (spPrivateKey != null)
      saml2Setting.setSpPrivateKey(spPrivateKey);
	}



	/**
	 * @param saml2Setting
	 */
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

package com.onelogin.saml2.settings;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.onelogin.saml2.model.Contact;
import com.onelogin.saml2.model.Organization;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.SchemaFactory;
import com.onelogin.saml2.util.Util;

public final class MetaBasedSettingsBuilder {

  public static final String IDP_ENTITY_ID_XPATH = "/md:EntityDescriptor";
  public static final String IDP_NAME_ID_FORMAT_XPATH = "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat";

  public static final String IDP_SSO_LOCATION_XPATH = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService";
  public static final String IDP_SLO_LOCATION_XPATH = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService";

  public static final String IDP_CERT_XPATH = "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate";

  public static final String IDP_ORG_XPATH = "/md:EntityDescriptor/md:Organization";
  public static final String IDP_ORG_NAME_XPATH = "/md:EntityDescriptor/md:Organization/md:OrganizationName";
  public static final String IDP_ORG_DISPLAY_NAME_XPATH = "/md:EntityDescriptor/md:Organization/md:OrganizationDisplayName";
  public static final String IDP_ORG_URL_XPATH = "/md:EntityDescriptor/md:Organization/md:OrganizationURL";

  public static final String IDP_CONTACT_SUPPORT_XPATH = "/md:EntityDescriptor/md:ContactPerson[@contactType='support']";
  public static final String IDP_CONTACT_TECH_XPATH = "/md:EntityDescriptor/md:ContactPerson[@contactType='technical']";

  public static final String IDP_CONTACT_NAME_XPATH = "/md:EntityDescriptor/md:ContactPerson[@contactType='%s']/md:GivenName";
  public static final String IDP_CONTACT_EMAIL_XPATH = "/md:EntityDescriptor/md:ContactPerson[@contactType='%s']/md:EmailAddress";

  private Boolean strict = false;
  private Boolean debug = false;

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
  private String idpMetadataLocation;
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
  /*
   * SECURITY_NAMEID_ENCRYPTED = "onelogin.saml2.security.nameid_encrypted";
   * SECURITY_AUTHREQUEST_SIGNED = "onelogin.saml2.security.authnrequest_signed";
   * SECURITY_LOGOUTREQUEST_SIGNED = "onelogin.saml2.security.logoutrequest_signed";
   * SECURITY_LOGOUTRESPONSE_SIGNED = "onelogin.saml2.security.logoutresponse_signed";
   * SECURITY_WANT_MESSAGES_SIGNED = "onelogin.saml2.security.want_messages_signed";
   * SECURITY_WANT_ASSERTIONS_SIGNED = "onelogin.saml2.security.want_assertions_signed";
   * SECURITY_WANT_ASSERTIONS_ENCRYPTED = "onelogin.saml2.security.want_assertions_encrypted";
   * SECURITY_WANT_NAMEID = "onelogin.saml2.security.want_nameid"; SECURITY_WANT_NAMEID_ENCRYPTED =
   * "onelogin.saml2.security.want_nameid_encrypted"; SECURITY_SIGN_METADATA =
   * "onelogin.saml2.security.sign_metadata"; SECURITY_REQUESTED_AUTHNCONTEXT =
   * "onelogin.saml2.security.requested_authncontext"; SECURITY_REQUESTED_AUTHNCONTEXTCOMPARISON =
   * "onelogin.saml2.security.requested_authncontextcomparison"; SECURITY_WANT_XML_VALIDATION =
   * "onelogin.saml2.security.want_xml_validation"; SECURITY_SIGNATURE_ALGORITHM =
   * "onelogin.saml2.security.signature_algorithm";
   * SECURITY_REJECT_UNSOLICITED_RESPONSES_WITH_INRESPONSETO =
   * "onelogin.saml2.security.reject_unsolicited_responses_with_inresponseto";
   */

  private final List<Contact> contacts = new ArrayList<>();
  private Organization organization;

  private MetaBasedSettingsBuilder() {

  }

  public static MetaBasedSettingsBuilder builder() {
    return new MetaBasedSettingsBuilder();
  }

  public MetaBasedSettingsBuilder withIdpEntityId(String idpEntityId) {
    this.idpEntityId = idpEntityId;
    return this;
  }

  public MetaBasedSettingsBuilder strict() {
    this.strict = true;
    return this;
  }

  public MetaBasedSettingsBuilder debug() {
    this.debug = true;
    return this;
  }

  public MetaBasedSettingsBuilder withIdPMetadataLocation(String metadata) {
    this.idpMetadataLocation = metadata;
    return this;
  }

  public MetaBasedSettingsBuilder withOrganization(String name, String displayName, String url) {
    this.organization = new Organization(name, displayName, url);
    return this;
  }

  public MetaBasedSettingsBuilder withTechnicalContact(String name, String email) {
    contacts.add(new Contact("technical", name, email));
    return this;
  }

  public MetaBasedSettingsBuilder withSupportContact(String name, String email) {
    contacts.add(new Contact("supprort", name, email));
    return this;
  }

  public MetaBasedSettingsBuilder withSpEntityId(String spEntityId) {
    this.spEntityId = spEntityId;
    return this;
  }


  public MetaBasedSettingsBuilder withAcsUrl(String acsUrl) {
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
  public Saml2Settings build()  {
    Saml2Settings saml2Setting = new Saml2Settings();
    /*if (!StringUtils.isEmpty(propertiesFileLocation)) {
      saml2Setting = new FileBasedSettingsBuilder().fromFile(propertiesFileLocation).build();
    } else if (properties != null) {
      saml2Setting = new FileBasedSettingsBuilder().fromProperties(properties).build();
    } else {
      saml2Setting = new Saml2Settings();
    }*/

    saml2Setting.setStrict(strict);
    saml2Setting.setDebug(debug);

    // First load from metadata if we have any
    if (StringUtils.isNotEmpty(idpMetadataLocation)) {
      loadSettingsFromMetadata(saml2Setting);
    }

    // Now load the rest overriding if values have been set
    buildSpSetting(saml2Setting);
    setIdpSettings(saml2Setting);

    if (!contacts.isEmpty())
      saml2Setting.setContacts(contacts);

    if (organization != null)
      saml2Setting.setOrganization(organization);

    setSecuritySettings(saml2Setting);
    return saml2Setting;
  }


  /**
   * Loads the SP settings from the properties file
   */
  private void buildSpSetting(Saml2Settings saml2Setting) {
    saml2Setting.setSpEntityId(spEntityId);
    saml2Setting.setSpAssertionConsumerServiceUrl(createUrl(acsUrl));
    saml2Setting.setSpAssertionConsumerServiceBinding(acsUrlBinding);
    saml2Setting.setSpSingleLogoutServiceUrl(createUrl(spSloURL));
    saml2Setting.setSpSingleLogoutServiceBinding(spSloBinding);
    saml2Setting.setSpNameIDFormat(nameIdFormat);

    saml2Setting.setSpX509cert(createCertificate(spX509Cert));
    saml2Setting.setSpPrivateKey(createPrivateKey(spPrivateKey));
  }


  /**
   * Load the settings which are available via the IdP metadata file.
   *
   * @param saml2Setting
   */
  private void loadSettingsFromMetadata(Saml2Settings saml2Setting) {
    try {
      Document doc = Util.convertStringToDocument(Util.getAbsoluteFileAsString(idpMetadataLocation));
      if (!Util.validateXML(doc, SchemaFactory.SAML_SCHEMA_METADATA_2_0)) {
        throw new RuntimeException("Idp configuration at [" + idpMetadataLocation + "] invalid");
      }

      NodeList workingNodeList = Util.query(doc, IDP_ENTITY_ID_XPATH);
      if (workingNodeList.getLength() == 1)
        saml2Setting.setIdpEntityId(workingNodeList.item(0).getAttributes().getNamedItem("entityID").getTextContent());

      workingNodeList = Util.query(doc, IDP_SSO_LOCATION_XPATH);
      if (workingNodeList.getLength() > 0) {
        saml2Setting.setIdpSingleSignOnServiceUrl(
          createUrl(getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Location").getNodeValue()));
        saml2Setting.setIdpSingleSignOnServiceBinding(
          getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Binding").getNodeValue());
      }

      // Set the x509 cert for the Idp
      String cert = getValueOfSingleNodeIfPresent(doc, IDP_CERT_XPATH);
      if (cert != null)
        saml2Setting.setIdpx509cert(createCertificate(cert));

      // Set SLO values
      workingNodeList = Util.query(doc, IDP_SLO_LOCATION_XPATH);
      if (workingNodeList.getLength() > 0) {
        saml2Setting.setIdpSingleLogoutServiceUrl(
          createUrl(getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Location").getNodeValue()));
        saml2Setting.setIdpSingleLogoutServiceBinding(getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Binding").getNodeValue());
      }

      // Organization
      workingNodeList = Util.query(doc, IDP_ORG_XPATH);
      if (workingNodeList.getLength() == 1) {
        saml2Setting.setOrganization(new Organization(
          getValueOfSingleNodeIfPresent(doc, IDP_ORG_NAME_XPATH),
          getValueOfSingleNodeIfPresent(doc, IDP_ORG_DISPLAY_NAME_XPATH),
          getValueOfSingleNodeIfPresent(doc, IDP_ORG_URL_XPATH)));
      }

      // Contacts
      if (Util.query(doc, IDP_CONTACT_TECH_XPATH).getLength() == 1)
        saml2Setting.getContacts().add(buildContact(doc, "technical"));

      if (Util.query(doc, IDP_CONTACT_SUPPORT_XPATH).getLength() == 1)
        saml2Setting.getContacts().add(buildContact(doc, "support"));

    } catch(Exception e) {
      throw new RuntimeException(e);
    }
  }


  /**
   * Returns the contents of single node matching the provided XPath. If there is more
   * than one node or none are matched it will {@linkplain Optional#absent()};
   *
   * @param doc the document to check
   * @param xPath the XPath to use for the check
   * @return the contents of the single node.
   */
  private String getValueOfSingleNodeIfPresent(Document doc, String xPath) {
    try {
      NodeList workingNodeList = Util.query(doc, xPath);
      if (workingNodeList.getLength() == 1) {
        return workingNodeList.item(0).getTextContent();
      }
    } catch (XPathExpressionException e) {
      throw new RuntimeException(e);
    }

    return null;
  }


  /**
   * Build a {@linkplain Contact} if we have both the name and email
   * address for a contact of the given type.
   *
   * @param doc the doc to check
   * @param type the contact type to check for
   * @return A populated contact
   */
  private Contact buildContact(Document doc, String type) {
    String name = getValueOfSingleNodeIfPresent(doc, String.format(IDP_CONTACT_NAME_XPATH, type));
    String email = getValueOfSingleNodeIfPresent(doc, String.format(IDP_CONTACT_EMAIL_XPATH, type));

    if (StringUtils.isNotEmpty(name) && StringUtils.isNotEmpty(email)) {
      return new Contact(type, name, email);
    } else {
      return null;
    }
  }


  /**
   * Get the value of a node matching on a attribute value from a {@linkplain NodeList}.
   *
   * @param nl the nodelist to check
   * @param attribute the attribute to check
   * @param attributeValue the value of the attribute being matched on
   * @return The {@linkplain Node} which matches on the specified attribute
   */
  private Node getValueOfNodeMatchingAttribute(NodeList nl, String attribute, String attributeValue) {
    for(int i=0; i<nl.getLength(); i++) {
      Node current = nl.item(i);
      if (attributeValue.equals(current.getAttributes().getNamedItem(attribute).getTextContent())) {
        return current;
      }
    }
    throw new IllegalArgumentException("Could not find node with attribute [" + attribute + "] with value [" + attributeValue + "] in metadata file [" + idpMetadataLocation + "].");
  }


  /**
   * Set the IdP settings provided via the chained builder methods. These
   * take precedence over those provided in a metadata file. This allows
   * the values to be overridden if required.
   *
   * @param saml2Setting the settings to populate
   */
  private void setIdpSettings(Saml2Settings saml2Setting) {
    if (StringUtils.isNotEmpty(idpEntityId))
      saml2Setting.setIdpEntityId(idpEntityId);

    if (StringUtils.isNotEmpty(ssoServiceUrl))
      saml2Setting.setIdpSingleSignOnServiceUrl(createUrl(ssoServiceUrl));

    if (StringUtils.isNotEmpty(ssoBinding))
      saml2Setting.setIdpSingleSignOnServiceBinding(ssoBinding);

    if (StringUtils.isNotEmpty(idpSloUrl))
      saml2Setting.setIdpSingleLogoutServiceUrl(createUrl(idpSloUrl));

    if (StringUtils.isNotEmpty(idpSloResponseUrl))
      saml2Setting.setIdpSingleLogoutServiceResponseUrl(createUrl(idpSloResponseUrl));

    if (StringUtils.isNotEmpty(idpSloBinding))
      saml2Setting.setIdpSingleLogoutServiceBinding(idpSloBinding);

    if (StringUtils.isNotEmpty(idpX509Cert))
      saml2Setting.setIdpx509cert(createCertificate(idpX509Cert));

    if (StringUtils.isNotEmpty(idpCertFingerprint))
      saml2Setting.setIdpCertFingerprint(idpCertFingerprint);

    if (StringUtils.isNotEmpty(idpCertFingerPrintAlgorithm))
      saml2Setting.setIdpCertFingerprintAlgorithm(idpCertFingerPrintAlgorithm);
  }


  /**
   * Set the security settings from the chained builder provided values.
   *
   * @param saml2Setting the settings to populate.
   */
  private void setSecuritySettings(Saml2Settings saml2Setting) {
    //TODO
  }


  /**
   * Loads a property of the type X509Certificate from the Properties object
   *
   * @param propertyKey
   *            the property name
   *
   * @return the X509Certificate object
   */
  protected X509Certificate createCertificate(String certString) {
    if (certString == null || certString.isEmpty()) {
      return null;
    } else {
      try {
        return Util.loadCert(certString);
      } catch (Exception e) {
        return null;
      }
    }
  }


  protected PrivateKey createPrivateKey(String keyString) {
    if (keyString == null || keyString.isEmpty()) {
      return null;
    } else {
      try {
        return Util.loadPrivateKey(keyString);
      } catch (Exception e) {
        return null;
      }
    }
  }


  /**
   * Loads a property of the type URL from the Properties object
   *
   * @param propertyKey
   *            the property name
   *
   * @return the value
   */
  private URL createUrl(String urlPropValue) {
    if (urlPropValue == null || urlPropValue.isEmpty()) {
      return null;
    } else {
      try {
        return new URL(urlPropValue.trim());
      } catch (MalformedURLException e) {
        return null;
      }
    }
  }
}
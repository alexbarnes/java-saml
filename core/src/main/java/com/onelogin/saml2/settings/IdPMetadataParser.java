package com.onelogin.saml2.settings;

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

/**
 * Parser for {@linkplain Saml2Settings} provided in a SAML Idp metadata file.
 *
 */
public final class IdPMetadataParser {

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


  /**
   * Set an properties provided in the metadata on the {@linkplain Saml2Settings}
   * which are passed in.
   *
   * @param settings the settings to populate
   * @param metadata the metadata to parse for settings
   *
   */
  public static void parse(Saml2Settings settings, String metadata)  {
    if (StringUtils.isNotEmpty(metadata)) {
      loadSettingsFromMetadata(settings, metadata);
    }
  }


  /**
   * Load the settings which are available via the IdP metadata file.
   *
   * @param saml2Setting the setting to populate
   * @param the metadata to parse
   *
   */
  private static void loadSettingsFromMetadata(Saml2Settings saml2Setting, String metadata) {
    try {
      Document doc = Util.convertStringToDocument(metadata);
      if (!Util.validateXML(doc, SchemaFactory.SAML_SCHEMA_METADATA_2_0)) {
        throw new RuntimeException("Idp configuration invalid");
      }

      NodeList workingNodeList = Util.query(doc, IDP_ENTITY_ID_XPATH);
      if (workingNodeList.getLength() == 1)
        saml2Setting.setIdpEntityId(workingNodeList.item(0).getAttributes().getNamedItem("entityID").getTextContent());

      workingNodeList = Util.query(doc, IDP_SSO_LOCATION_XPATH);
      if (workingNodeList.getLength() > 0) {
        saml2Setting.setIdpSingleSignOnServiceUrl(
          Util.createUrl(getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Location").getNodeValue()));
        saml2Setting.setIdpSingleSignOnServiceBinding(
          getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Binding").getNodeValue());
      }

      // Set the x509 cert for the Idp
      String cert = getValueOfSingleNodeIfPresent(doc, IDP_CERT_XPATH);
      if (cert != null)
        saml2Setting.setIdpx509cert(Util.createCertificate(cert));

      // Set SLO values
      workingNodeList = Util.query(doc, IDP_SLO_LOCATION_XPATH);
      if (workingNodeList.getLength() > 0) {
        saml2Setting.setIdpSingleLogoutServiceUrl(
          Util.createUrl(getValueOfNodeMatchingAttribute(workingNodeList, "Binding", Constants.BINDING_HTTP_REDIRECT).getAttributes().getNamedItem("Location").getNodeValue()));
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
   * than one node or none are matched it will return null;
   *
   * @param doc the document to check
   * @param xPath the XPath to use for the check
   * @return the contents of the single node.
   */
  private static String getValueOfSingleNodeIfPresent(Document doc, String xPath) {
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
  private static Contact buildContact(Document doc, String type) {
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
  private static Node getValueOfNodeMatchingAttribute(NodeList nl, String attribute, String attributeValue) {
    for(int i=0; i<nl.getLength(); i++) {
      Node current = nl.item(i);
      if (attributeValue.equals(current.getAttributes().getNamedItem(attribute).getTextContent())) {
        return current;
      }
    }
    throw new IllegalArgumentException("Could not find node with attribute [" + attribute + "] with value [" + attributeValue + "] in metadata file.");
  }
}
package com.arun.digital.security.standards;

import com.helger.xmldsig.keyselect.ContainedX509KeySelector;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class DigitalSign {

    static {
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
    }

    public static void main(String[] args) throws Exception {

        String keystoreType = "JKS";
        String keystoreFile = "C:\\SpringBootPoc\\digital-sign-poc\\src\\main\\resources\\arun.jks";
        String keystorePass = "arun1232";
        String privateKeyAlias = "arun";
        String privateKeyPass = "arun1232";
        File signatureFile = new File("C:\\SpringBootPoc\\digital-sign-poc\\src\\main\\resources\\signedPurchaseOrder.xml");
        //SOAP envelope to be signed
        File purchaseOrder = new File("C:\\SpringBootPoc\\digital-sign-poc\\src\\main\\resources\\purchaseOrder.xml");
        Element element = null;

        // Create a DOM XMLSignatureFactory that will be used to generate the enveloped signature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList
                        (fac.newTransform
                                (Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
        // Create the SignedInfo.
        SignedInfo si = fac.newSignedInfo
                (fac.newCanonicalizationMethod
                                (CanonicalizationMethod.EXCLUSIVE,
                                        (C14NMethodParameterSpec) null),
                        fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                        Collections.singletonList(ref));

        // Load the KeyStore and get the signing key and certificate.
        KeyStore ks = KeyStore.getInstance(keystoreType);
        ks.load(new FileInputStream(keystoreFile), keystorePass.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry
                        (privateKeyAlias, new KeyStore.PasswordProtection(privateKeyPass.toCharArray()));
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        final X509IssuerSerial issuer = kif.newX509IssuerSerial(cert.getIssuerX500Principal().getName(), cert.getSerialNumber());
        x509Content.add(issuer);
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(purchaseOrder));

        // Create a DOMSignContext and specify the RSA PrivateKey and location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        // Output the resulting document.
        OutputStream os = new FileOutputStream(signatureFile);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        // Validating an XML Signature Find Signature element.
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        // Create a DOMValidateContext and specify a KeySelector
        // and document context.
        DOMValidateContext valContext = new DOMValidateContext
                (new ContainedX509KeySelector(), nl.item(0));

        // Unmarshal the XMLSignature.
        XMLSignature signature1 = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature.
        boolean coreValidity = signature1.validate(valContext);


        // Check core validation status.
        if (!coreValidity) {
            System.err.println("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            if (!sv) {
                // Check the validation status of each Reference.
                Iterator i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((Reference) i.next()).validate(valContext);
                    System.out.println("ref[" + j + "] validity status: " + refValid);
                }
            }
        } else {
            System.out.println("Signature passed core validation");
        }

        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        // Unmarshal the XMLSignature.
        XMLSignature signature2 = fac.unmarshalXMLSignature(valContext);
        // Validate the XMLSignature.
        boolean coreValidity1 = signature2.validate(valContext);

        Iterator i = signature2.getSignedInfo().getReferences().iterator();
        for (int j = 0; i.hasNext(); j++) {
            InputStream is = ((Reference) i.next()).getDigestInputStream();
            // Display the data.
        }

    }

}

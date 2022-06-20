package com.ak.signature;

import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How to use XmlSigner
 */
public class XmlSignerTest {

    static {
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
    }

    @Test
    public void shouldSignXmlUsingAJavaKeyStore() throws Exception {
        // scenario
        InputStream jks = XmlSigner.class.getResourceAsStream("/arun.jks");
        File signatureFile = new File("C:\\SpringBootPoc\\digital-sign-poc\\src\\main\\resources\\xml-document-sample-result.xml");

        String alias = "arun";
        String password = "arun1232";

        // action
        SignedXml signedXml = new XmlSigner()
                .withXml("\n<request>"
                        + "\n<another-tag name='foo'/>"
                        + "\n</request>")  // it supports InputStream as well
                .withKeyStore(jks, alias, password)
                .sign();

        // validation
        String content = signedXml.getContent();
 //       System.out.println("content:" + content);  // just prints the result

        //Call method to convert XML string content to XML Document object.
        //Now you can perform required operations on this XML doc
        Document doc = convertStringToXMLDoc(content);

        //Get the first node of XML Document to validate whether XML document is build correctly
        System.out.println("XML Doc First Node Value is : " + doc.getFirstChild().getNodeName());


        // Output the resulting document.
        OutputStream os = new FileOutputStream(signatureFile);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        assertThat(content)
                .contains("<X509Certificate>")
                .contains("</X509Data>")
                .contains("</Signature>");
    }

    //Following method will  to convert String to XML Document
    private static Document convertStringToXMLDoc(String strXMLValue) {

        try {
            //Create a new object of DocumentBuilderFactory
            DocumentBuilderFactory dbfactory = DocumentBuilderFactory.newInstance();

            //Create an object DocumentBuilder to parse the specified XML Data
            DocumentBuilder builder = dbfactory.newDocumentBuilder();

            //Parse the content to Document object
            Document doc = builder.parse(new InputSource(new StringReader(strXMLValue)));
            return doc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

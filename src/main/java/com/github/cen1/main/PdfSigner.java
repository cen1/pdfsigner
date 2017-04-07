package com.github.cen1.main;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.UUID;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import com.github.cen1.PdfException;
import com.github.cen1.KeystoreException;

public class PdfSigner {
		
	public static byte[] signDetached(byte[] data) throws PdfException {
        
		try {
			PDDocument document=PDDocument.load(data);
			
			int accessPermissions = getMDPPermission(document);
			
			KeyStore ks = KeystoreUtil.getInternalKeyStore();
			X509Certificate cert = (X509Certificate)KeystoreUtil.getKeyEntry(ks).getCertificate();
			
			String cn = KeystoreUtil.getDN(cert, "CN");
			String st = KeystoreUtil.getDN(cert, "ST");
	
	        // Create signature dictionary
	        PDSignature signature = new PDSignature();
	        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
	        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_X509_RSA_SHA1);
	        signature.setName(cn);
	        signature.setLocation(st);
	        signature.setReason("a reason");
	
	        // The signing date, needed for valid signature
	        signature.setSignDate(Calendar.getInstance());
	
	        // Register signature dictionary and sign interface
	        document.addSignature(signature);
	        
	        //Protect
	        AccessPermission ap = new AccessPermission();
	        ap.setReadOnly();
	        ap.setCanFillInForm(false);
	        ap.setCanModify(false);
	        ap.setCanModifyAnnotations(false);
	        
	        StandardProtectionPolicy spp = new StandardProtectionPolicy(UUID.randomUUID().toString(), "", ap);
	        document.protect(spp);
	        
	        //Certify
	        if (accessPermissions == 0) {
	        	System.out.println("Pdf will be certified");
	            setMDPPermission(document, signature, 2);
	        }  
	
	        // Write incremental (only for signing purpose)
	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	        document.save(out);
	        document.close();
	        
	        return out.toByteArray();
		}
		catch (KeystoreException | IOException e) {
			throw new PdfException();
		}
    }
	
	private static int getMDPPermission(PDDocument doc)
    {
        COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary)
        {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary)
            {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject("Reference");
                if (base instanceof COSArray)
                {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod")))
                            {
                                base = sigRefDict.getDictionaryObject("TransformParams");
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    private static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
    {
        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
        referenceDict.setItem("TransformMethod", COSName.getPDFName("DocMDP"));
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
        referenceDict.setItem("TransformParams", transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem("Reference", referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }
}

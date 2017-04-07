package com.github.cen1.main;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import com.github.cen1.KeystoreException;

public class KeystoreUtil {
	
	public static KeyStore getInternalKeyStore() throws KeystoreException {
		ClassLoader classLoader = KeystoreUtil.class.getClassLoader();
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(classLoader.getResourceAsStream("internal/keystore.jks"), "changeit".toCharArray());
			return ks;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new KeystoreException();
		}
	}
	
	public static PrivateKeyEntry getKeyEntry(KeyStore ks) throws KeystoreException {
		
		try {
			PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("cen1",
					new KeyStore.PasswordProtection("changeit".toCharArray()));
			return keyEntry;
		}
		catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new KeystoreException();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static KeyInfo getKeyInfo(XMLSignatureFactory fac, PrivateKeyEntry keyEntry) {
		
		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

		// Create the KeyInfo containing the X509Data.
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		
		List x509Content = new ArrayList();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

		return ki;
	}
	
	public static String getDN(X509Certificate cert, String type) throws KeystoreException {
		
		String dn = cert.getSubjectX500Principal().getName();
		LdapName ln;
		try {
			ln = new LdapName(dn);

			for(Rdn rdn : ln.getRdns()) {
			    if(rdn.getType().equalsIgnoreCase(type)) {
			        return rdn.getValue().toString();
			    }
			}
		}
		catch (InvalidNameException e) {
			throw new KeystoreException();
		}
		
		return null;
	}
}

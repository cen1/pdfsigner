package com.github.cen1.main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.github.cen1.PdfException;

public class Main {
	
	public static void main(String[] args) throws IOException, PdfException {
		
		ClassLoader classLoader = Main.class.getClassLoader();
		InputStream in = classLoader.getResourceAsStream("internal/unsigned.pdf");
		
		byte[] unsigned = IOUtils.toByteArray(in);
		byte[] signed = PdfSigner.signDetached(unsigned);
		
		FileUtils.writeByteArrayToFile(new File(args[0]), signed);
	}
}

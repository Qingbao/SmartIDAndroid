package hig.no.smartid.service;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import hig.no.smartid.lds.DG_14_FILE;
import hig.no.smartid.lds.DG_15_FILE;
import hig.no.smartid.lds.DG_1_FILE;
import hig.no.smartid.lds.DG_2_FILE;
import hig.no.smartid.lds.DG_3_FILE;
import hig.no.smartid.lds.DG_COM;
import hig.no.smartid.lds.DG_SOD;
import hig.no.smartid.lds.FileStructure;
import hig.no.smartid.lds.SecurityObjectIndicator;
import android.util.Log;
import net.sourceforge.scuba.smartcards.APDUEvent;
import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ResponseAPDU;
import net.sourceforge.scuba.util.Hex;

public class Reader implements APDUListener{
	
	private static final String NONE = "<NONE>";
	
	private DG_1_FILE dg1file = null;

	private DG_2_FILE dg2file = null;

	private DG_3_FILE dg3file = null;

	private DG_14_FILE dg14file = null;

	private DG_15_FILE dg15file = null;

	private DG_SOD sodFile = null;

	private DG_COM comFile = null;

	private SmartID smartID = null;

	private boolean debug = true;
	
	private BasicInfo bi = null;

	@Override
	public void exchangedAPDU(APDUEvent apduEvent) {
		CommandAPDU c = apduEvent.getCommandAPDU();
		ResponseAPDU r = apduEvent.getResponseAPDU();
		if (debug) {
			Log.v("C: " , Hex.bytesToHexString(c.getBytes()));
			Log.v("R: " , Hex.bytesToHexString(r.getBytes()));
		}
		
	}
	
	
	
	public void readData() {
		List<Short> files = smartID.getFileList();
		InputStream in = null;
		Short fid = BasicService.EF_COM;
		files.remove(fid);
		try {
			fid = BasicService.EF_DG1;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				dg1file = new DG_1_FILE(in);
				bi = dg1file.getInfo();
				Log.i(null, "DG1 ok");
				files.remove(fid);
			}
			/*fid = BasicService.EF_DG2;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				dg2file = new DG_2_FILE(in);
				Log.i(null, "DG2 ok");
				files.remove(fid);
			}*/
			/*fid = BasicService.EF_DG3;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				dg3file = new DG_3_FILE(in);
				
				files.remove(fid);
			}*/
			/*fid = BasicService.EF_DG15;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				dg15file = new DG_15_FILE(in);
				Log.i(null, "DG15 ok");
				files.remove(fid);
			}*/
			/*fid = BasicService.EF_DG14;
			if (files.contains(fid)) {
				in = passwdManager.getInputStream(fid);
				dg14file = new DG_14_FILE(in);
				
				files.remove(fid);
			}*/
			fid = BasicService.EF_SOD;
			if (files.contains(fid)) {
				in = smartID.getInputStream(fid);
				sodFile = new DG_SOD(in);
				Log.i(null, "DG SOD ok");
				
				files.remove(fid);
			}
			// See if there are any files that we did not know
			// how to handle:
			for (Short f : files) {
				Log.i("Don't know how to handle file ID: "
						, Hex.shortToHexString(f));
			}
			
		} catch (Exception ioe) {
			ioe.printStackTrace();
		}
	}
	
	public String getSur(){
		return bi.sur;
	}
	
	public String getGiven(){
		return bi.given;
	}
	
	public String getGender(){
		return bi.gender;
	}
	
	public String getDOB(){
		return bi.dob;
	}
	
	public String getPOB(){
		return bi.pob;
	}
	
	public String getDOI(){
		return bi.issue;
	}
	
	public String getDOE(){
		return bi.expriy;
	}
	
	public String getIC(){
		return bi.country;
	}
	
	public String getIA(){
		return bi.authority;
	}
	
	public String getPN(){
		return bi.id;
	}

	// Check all kinds of security integrity things on the license data read in
	public void verifySecurity(BasicService service) {
		/*if (dg15file != null) {
			PublicKey k = dg15file.getPublicKey();
			try {
				boolean result = service.doAA(k);
				if (result) {
					//statusBar.setAAOK();
					Log.d(null, "AAOK");
				} else {
					//statusBar.setAAFail("wrong signature");
					Log.d(null, "AAFAIL");
				}
			} catch (CardServiceException cse) {
				//statusBar.setAAFail(cse.getMessage());
			}
		} else {
			//statusBar.setAANotChecked();
			Log.d(null, "AANOTCHECKED");
		}*/

		List<Integer> comDGList = new ArrayList<Integer>();
		for (Integer tag : comFile.getTagList()) {
			comDGList.add(FileStructure.lookupDataGroupNumberByTag(tag));
		}
		Collections.sort(comDGList);

		Map<Integer, byte[]> hashes = sodFile.getDataGroupHashes();

		List<Integer> tagsOfHashes = new ArrayList<Integer>();
		tagsOfHashes.addAll(hashes.keySet());
		Collections.sort(tagsOfHashes);
		if (!tagsOfHashes.equals(comDGList)) {
			//statusBar.setPAFail("\"Sanity check\" failed!");
			Log.d(null, "Sanity check failed!");
		} else {
			try {
				String digestAlgorithm = sodFile.getDigestAlgorithm();
				MessageDigest digest = MessageDigest
						.getInstance(digestAlgorithm);
				for (int dgNumber : hashes.keySet()) {
					short fid = FileStructure.lookupFIDByTag(FileStructure
							.lookupTagByDataGroupNumber(dgNumber));
					byte[] storedHash = hashes.get(dgNumber);

					digest.reset();

					InputStream dgIn = null;
					Exception exc = null;
					try {
						dgIn = smartID.getInputStream(fid);
					} catch (Exception ex) {
						exc = ex;
					}

					if (dgIn == null && smartID.hasEAC()
							&& !smartID.wasEACPerformed()
							&& smartID.getEACFiles().contains(fid)) {
						continue;
					} else {
						if (exc != null)
							throw exc;
					}

					byte[] buf = new byte[4096];
					while (true) {
						int bytesRead = dgIn.read(buf);
						if (bytesRead < 0) {
							break;
						}
						digest.update(buf, 0, bytesRead);
					}
					byte[] computedHash = digest.digest();
					if (!Arrays.equals(storedHash, computedHash)) {
						//statusBar.setPAFail("Authentication of DG" + dgNumber
						//		+ " failed");
						Log.d(null, "PAfailed!"+dgNumber);
						
					}	
					
				}
				//statusBar.setPAOK("Hash alg. " + digestAlgorithm);
				Log.d(null, "PAOK!");
			} catch (Exception e) {
				//statusBar.setPAFail(e.getMessage());
				Log.d(null, "PAfail!");
			}
		}
		try {
			X509Certificate docSigningCert = sodFile.getDocSigningCertificate();
			if (sodFile.checkDocSignature(docSigningCert)) {
				//statusBar.setDSOK("sig. alg. "
						//+ sodFile.getDigestEncryptionAlgorithm());
			} else {
				//statusBar.setDSFail("DS Signature incorrect");
			}
		} catch (Exception e) {
			e.printStackTrace();
			//statusBar.setDSFail(e.getMessage());
		}
	}

	// Make the COM file contents human readable
	private String formatComFile() {
		if (comFile == null)
			return NONE;
		List<Integer> list = comFile.getDGNumbers();
		String result = "Data groups:";
		for (Integer i : list) {
			result += " DG" + i.toString();
		}
		result += "\n";
		SecurityObjectIndicator[] sois = comFile.getSOIArray();
		if (sois.length > 0) {
			result += "Security Object Indicators:\n";
			for (SecurityObjectIndicator soi : sois) {
				result += "  " + soi.toString() + "\n";
			}
		}
		result = result.substring(0, result.length() - 1);
		return result;
	}
	
	public void setSmartID(SmartID pm) {
		this.smartID = pm;
	}
	
	public SmartID getSmartID() {
		return smartID;
	}
	
	public DG_COM getCOMFile() {
		return comFile;
	}

	public void setCOMFile(DG_COM comFile) {
		this.comFile = comFile;
	}

}

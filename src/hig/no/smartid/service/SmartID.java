
package hig.no.smartid.service;

import hig.no.smartid.certificate.TerminalCVCertificateDirectory;
import hig.no.smartid.lds.DG_14_FILE;
import hig.no.smartid.lds.DG_15_FILE;
import hig.no.smartid.lds.DG_1_FILE;
import hig.no.smartid.lds.DG_COM;
import hig.no.smartid.lds.DG_SOD;
import hig.no.smartid.lds.DocumentSigner;
import hig.no.smartid.lds.FileStructure;
import hig.no.smartid.lds.SecurityObjectIndicator;
import hig.no.smartid.lds.SecurityObjectIndicatorDG14;
import hig.no.smartid.lds.SecurityObjectIndicatorDG15;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

import net.sourceforge.scuba.smartcards.CardFileInputStream;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.util.Hex;

/**
 * A class for encapsulating the whole passwd manager contents: the files, and
 * the encryption keys. Can be intialized (a) almost empty, (b) from the
 * Service object (i.e. read in from the card), (c) form a ZIP
 * file containg the data groups.
 * 
 * 
 */
public class SmartID {

    private static final int BUFFER_SIZE = 243;

    private Map<Short, InputStream> rawStreams = new HashMap<Short, InputStream>();

    private Map<Short, InputStream> bufferedStreams = new HashMap<Short, InputStream>();

    private Map<Short, byte[]> filesBytes = new HashMap<Short, byte[]>();

    private Map<Short, Integer> fileLengths = new TreeMap<Short, Integer>();

    private Map<Short, Boolean> eapFlags = new TreeMap<Short, Boolean>();

    private int bytesRead = 0;

    private int totalLength = 0;

    // Our local copies of the COM and SOD files:
    private DG_COM comFile = null;

    private DG_SOD sodFile = null;

    private boolean eacSupport = false;

    private boolean eacSuccess = false;

    private CVCertificate cvcaCertificate = null;

    private PrivateKey eacPrivateKey = null;

    private PrivateKey aaPrivateKey = null;

    private DocumentSigner signer = null;
    
    private List<Short> eacFids = new ArrayList<Short>();

    private byte[] keySeed = null;
    
    private boolean updateCOMSODfiles = true;
    
    private BufferedInputStream preReadFile(BasicService service,
            short fid) throws CardServiceException {
        BufferedInputStream bufferedIn = null;
        if (rawStreams.containsKey(fid)) {
            int length = fileLengths.get(fid);
            bufferedIn = new BufferedInputStream(rawStreams.get(fid),
                    length + 1);
            bufferedIn.mark(length + 1);
            rawStreams.put(fid, bufferedIn);
            return bufferedIn;
        } else {
            service.getFileSystem().selectFile(fid);
            CardFileInputStream cardIn = service.readFile();
            int length = cardIn.getLength();
            bufferedIn = new BufferedInputStream(cardIn, length + 1);
            totalLength += length;
            fileLengths.put(fid, length);
            bufferedIn.mark(length + 1);
            rawStreams.put(fid, bufferedIn);
            return bufferedIn;
        }
    }

    private void setupFile(BasicService service, short fid)
            throws CardServiceException {
        service.getFileSystem().selectFile(fid);
        CardFileInputStream in = service.readFile();
        int fileLength = in.getLength();
        in.mark(fileLength + 1);
        rawStreams.put(fid, in);
        totalLength += fileLength;
        fileLengths.put(fid, fileLength);
    }

    /**
     * Constructor. Reads in the data from the card service.
     * 
     * @param service
     *            the card service
     * @throws IOException
     *             on problems
     * @throws CardServiceException
     *             on problems
     */
    public SmartID(BasicService service) throws IOException,
            CardServiceException {
        this(service, null);
    }

    /**
     * Constructor. Reads in the data from the card service.
     * 
     * @param service
     *            the card service
     * @param documentNumber
     *            the document number to use for EAC, if not provided (null) the
     *            one from DG1 will be used.
     * @throws IOException
     *             on problems
     * @throws CardServiceException
     *             on problems
     */
    public SmartID(BasicService service, String documentNumber)
            throws IOException, CardServiceException {

        BufferedInputStream bufferedIn = null;

        bufferedIn = preReadFile(service, BasicService.EF_COM);
        comFile = new DG_COM(bufferedIn);
        bufferedIn.reset();

        String caRef = null;

        SecurityObjectIndicator[] indicators = comFile.getSOIArray();
        for (SecurityObjectIndicator indicator : indicators) {
            if (indicator instanceof SecurityObjectIndicatorDG14) {
                eacSupport = true;
                SecurityObjectIndicatorDG14 i = (SecurityObjectIndicatorDG14) indicator;
                caRef = new String(i.getCertificateSubjectId(), 1, i
                        .getCertificateSubjectId()[0]);
                List<Integer> dgs = i.getDataGroups();
                for (Integer dg : dgs) {
                    eacFids.add(FileStructure
                            .lookupFIDByTag(FileStructure
                                    .lookupTagByDataGroupNumber(dg)));
                    eapFlags.put(FileStructure
                            .lookupFIDByTag(FileStructure
                                    .lookupTagByDataGroupNumber(dg)), true);
                }
            }
        }

        DG_14_FILE dg14file = null;
        for (int tag : comFile.getTagList()) {
            short fid = FileStructure.lookupFIDByTag(tag);
            if (fid == BasicService.EF_DG14) {
                //bufferedIn = preReadFile(service, BasicService.EF_DG14);
                //dg14file = new DG_14_FILE(bufferedIn);
                //bufferedIn.reset();
            } else {
                if (!eacFids.contains(fid)) {
                    setupFile(service, fid);
                }
            }
        }
        bufferedIn = preReadFile(service, BasicService.EF_SOD);
        sodFile = new DG_SOD(bufferedIn);
        bufferedIn.reset();
        // Try to do EAC
        if (eacSupport) {
            List<CVCertificate> termCerts = null;
            PrivateKey termKey = null;
            TerminalCVCertificateDirectory d = TerminalCVCertificateDirectory
                    .getInstance();
            if (caRef != null) {
                try {
                    List<CVCertificate> t = d.getCertificates(caRef);
                    if (t != null) {
                        termCerts = t;
                        termKey = d.getPrivateKey(caRef);
                    }
                } catch (NoSuchElementException nsee) {
                    nsee.printStackTrace();
                }
            }
            if (termCerts == null || termCerts.size() == 0) {
                // no luck, EAC present, but we don't have the certificates
                return;
            }
            // Try EAC
            if (documentNumber == null) {
                // Try DG1 if document number was not supplied
                bufferedIn = preReadFile(service, BasicService.EF_DG1);
                documentNumber = new DG_1_FILE(bufferedIn).getInfo().id;
                bufferedIn.reset();
            }

            // Map<Integer, PublicKey> cardKeys = dg14file.;
            Set<Integer> keyIds = dg14file.getIds();
            for (int i : keyIds) {
                try {
                    service.doEAC(i, dg14file.getKey(i), termCerts, termKey,
                            documentNumber);
                    eacSuccess = true;
                    break;
                } catch (CardServiceException cse) {
                    cse.printStackTrace();
                }
            }
            if (eacSuccess) {
                for (Short fid : eacFids) {
                    setupFile(service, fid);
                }
            }
        }
    }

   
    /**
     * Gets an inputstream that is ready for reading.
     * 
     * @param fid
     * @return the input stream for reading
     */
    public synchronized InputStream getInputStream(final short fid) {
        try {
            InputStream in = null;
            byte[] file = filesBytes.get(fid);
            if (file != null) {
                /* Already completely read this file. */
                in = new ByteArrayInputStream(file);
                in.mark(file.length + 1);
            } else {
                /* Maybe partially read? Use the buffered stream. */
                in = bufferedStreams.get(fid); // FIXME: some thread may
                // already be reading this one?
                if (in != null && in.markSupported()) {
                    in.reset();
                }
            }
            if (in == null) {
                /* Not read yet. Start reading it. */
                startCopyingRawInputStream(fid);
                in = bufferedStreams.get(fid);
            }
            return in;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new IllegalStateException("ERROR: " + ioe.toString());
        }
    }

    /**
     * Starts a thread to read the raw inputstream.
     * 
     * @param fid
     * @throws IOException
     */
    public synchronized void startCopyingRawInputStream(final short fid)
            throws IOException {
        final SmartID dl = this;
        final InputStream unBufferedIn = rawStreams.get(fid);
        if (unBufferedIn == null) {
            throw new IOException("No raw inputstream to copy "
                    + Integer.toHexString(fid));
        }
        final int fileLength = fileLengths.get(fid);
        unBufferedIn.reset();
        final PipedInputStream pipedIn = new PipedInputStream(fileLength + 1);
        final PipedOutputStream out = new PipedOutputStream(pipedIn);
        final ByteArrayOutputStream copyOut = new ByteArrayOutputStream();
        InputStream in = new BufferedInputStream(pipedIn, fileLength + 1);
        in.mark(fileLength + 1);
        bufferedStreams.put(fid, in);
        (new Thread(new Runnable() {
            public void run() {
                byte[] buf = new byte[BUFFER_SIZE];
                try {
                    while (true) {
                        int bytesRead = unBufferedIn.read(buf);
                        if (bytesRead < 0) {
                            break;
                        }
                        out.write(buf, 0, bytesRead);
                        copyOut.write(buf, 0, bytesRead);
                        dl.bytesRead += bytesRead;
                    }
                    out.flush();
                    out.close();
                    copyOut.flush();
                    byte[] copyOutBytes = copyOut.toByteArray();
                    filesBytes.put(fid, copyOutBytes);
                    copyOut.close();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                    /* FIXME: what if something goes wrong inside this thread? */
                }
            }
        })).start();
    }

    /**
     * Puts/replaces the given file in this card. Triggers all
     * necessary changes (COM/SOD file update, resigning, etc.)
     * 
     * @param fid
     *            the FID of the file
     * @param bytes
     *            the file contents
     */
    public void putFile(short fid, byte[] bytes) {
        putFile(fid, bytes, false);
    }

    /**
     * Puts/replaces the given file in this card. Triggers all
     * necessary changes (COM/SOD file update, resigning, etc.)
     * 
     * @param fid
     *            the FID of the file
     * @param bytes
     *            the file contents
     * @param eacProtection
     *            whether the file should be EAC protected
     */
    public void putFile(short fid, byte[] bytes, boolean eacProtection) {
        if (bytes == null) {
            return;
        }
        updateCOMSODfiles = true;
        filesBytes.put(fid, bytes);
        eapFlags.put(fid, eacProtection);
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        int fileLength = bytes.length;
        in.mark(fileLength + 1);
        bufferedStreams.put(fid, in);
        fileLengths.put(fid, fileLength);
        // FIXME: is this necessary?
        totalLength += fileLength;
        if (fid != BasicService.EF_COM
                && fid != BasicService.EF_SOD) {
            updateCOMSODFile(null);
        }
    }

    /**
     * Removes the given file in this card. Triggers all necessary
     * changes (COM/SOD file update, resigning, etc.)
     * 
     * @param fid
     *            the FID of the file to be removed
     */
    public void removeFile(short fid) {
        filesBytes.remove(fid);
        eapFlags.remove(fid);
        int fileLength = fileLengths.get(fid);
        bufferedStreams.remove(fid);
        fileLengths.remove(fid);
        totalLength -= fileLength;
        if (fid != BasicService.EF_COM
                && fid != BasicService.EF_SOD) {
            updateCOMSODFile(null);
        }
    }

    private void updateCOMSODFile(X509Certificate newCertificate) {
        if(!updateCOMSODfiles || sodFile == null || comFile == null) {
            return;
        }
        try {
            String digestAlg = sodFile.getDigestAlgorithm();
            X509Certificate cert = newCertificate != null ? newCertificate
                    : sodFile.getDocSigningCertificate();
            //String signatureAlg = sodFile.getDigestEncryptionAlgorithm();
            String signatureAlg = cert.getSigAlgName();
            
            byte[] signature = sodFile.getEncryptedDigest();
            Map<Integer, byte[]> dgHashes = new TreeMap<Integer, byte[]>();
            List<Short> dgFids = getFileList();
            if (dgFids.size() < 4) {
                // At least two proper data groups are needed to construct
                // a valid SOD
                return;
            }
            comFile.getTagList().clear();
            Collections.sort(dgFids);
            MessageDigest digest = MessageDigest.getInstance(digestAlg);
            for (Short fid : dgFids) {
                if (fid != BasicService.EF_COM
                        && fid != BasicService.EF_SOD) {
                    byte[] data = getFileBytes(fid);
                    byte tag = data[0];
                    dgHashes.put(FileStructure
                            .lookupDataGroupNumberByTag(tag), digest
                            .digest(data));
                    comFile.insertTag(new Integer(tag));
                }
            }
            if (signer != null) {
                signer.setCertificate(cert);
                sodFile = new DG_SOD(digestAlg, signatureAlg, dgHashes,
                        signer, cert);
            } else {
                sodFile = new DG_SOD(digestAlg, signatureAlg, dgHashes,
                        signature, cert);
            }
            updateSOIS();
            putFile(BasicService.EF_SOD, sodFile.getEncoded());
            putFile(BasicService.EF_COM, comFile.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Gets the contents of the given file.
     * 
     * @param fid
     *            the file's FID
     * @return the file contents
     */
    public byte[] getFileBytes(short fid) {
        byte[] result = filesBytes.get(fid);
        if (result != null) {
            return result;
        }
        InputStream in = getInputStream(fid);
        if (in == null) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[256];
        while (true) {
            try {
                int bytesRead = in.read(buf);
                if (bytesRead < 0) {
                    break;
                }
                out.write(buf, 0, bytesRead);
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
        return out.toByteArray();
    }

    /**
     * Sets the current document signer. Triggers all
     * necessary changes (COM/SOD file update, resigning, etc.)
     * 
     * @param signer
     *            the document signer
     */
    public void setSigner(DocumentSigner signer) {
        updateCOMSODfiles = true;
        this.signer = signer;
        updateCOMSODFile(null);
    }

    /**
     * Sets the current document signing certificate. Alters SOD file. Triggers
     * all necessary changes (COM/SOD file update, resigning, etc.)
     * 
     * @param newCertificate
     *            the new document signing certificate
     */
    public void setDocSigningCertificate(X509Certificate newCertificate) {
        updateCOMSODfiles = true;
        updateCOMSODFile(newCertificate);
    }

    // Helper: update the Security Object Indicators in the COM file
    private void updateSOIS() {
        if(!updateCOMSODfiles || comFile == null) {
            return;
        }
        SecurityObjectIndicatorDG15 soi15 = null;
        SecurityObjectIndicatorDG14 soi14 = null;
        if (getFileList().contains(BasicService.EF_DG15)
                && aaPrivateKey != null) {
            soi15 = new SecurityObjectIndicatorDG15(new ArrayList<Integer>());
        }
        if (getFileList().contains(BasicService.EF_DG14)
                && eacPrivateKey != null && cvcaCertificate != null) {
            List<Integer> dgs = new ArrayList<Integer>();
            for (short fid : getFileList()) {
                if (eapFlags.get(fid)) {
                    dgs.add(FileStructure.lookupDataGroupNumberByFID(fid));
                }
            }
            Collections.sort(dgs);
            soi14 = new SecurityObjectIndicatorDG14(cvcaCertificate, dgs);
        }
        int length = (soi15 != null ? 1 : 0) + (soi14 != null ? 1 : 0);
        SecurityObjectIndicator[] sois = new SecurityObjectIndicator[length];
        int index = 0;
        if (soi15 != null) {
            sois[index++] = soi15;
        }
        if (soi14 != null) {
            sois[index] = soi14;
        }
        comFile.setSOIArray(sois);
    }

    /**
     * Sets the current EAC CVCA certificate. Alters COM file. Triggers the
     * update of Security Object Indicators in the COM file.
     * 
     * @param cert
     *            the new EAC CVCA certificate
     */
    public void setCVCertificate(CVCertificate cert) {
        this.cvcaCertificate = cert;
        updateCOMSODfiles = true;
        updateSOIS();
    }

    /**
     * @return the stored EAC CVCA certificate
     */
    public CVCertificate getCVCertificate() {
        return cvcaCertificate;
    }

    /**
     * 
     * @return the current document signer
     */
    public DocumentSigner getSigner() {
        return signer;
    }

    /**
     * Sets the EAC key pair (alters DG14). Triggers all necessary changes
     * (COM/SOD file update, resigning, etc.)
     * 
     * @param keyPair
     *            the EAC key pair
     */
    public void setEAPKeys(KeyPair keyPair) {
        this.eacPrivateKey = keyPair.getPrivate();
        Map<Integer, PublicKey> key = new TreeMap<Integer, PublicKey>();
        key.put(-1, keyPair.getPublic());
        DG_14_FILE dg14file = new DG_14_FILE(key);
        putFile(BasicService.EF_DG14, dg14file.getEncoded());
    }

    /**
     * Sets the AA key pair (alters DG15). Triggers all necessary changes
     * (COM/SOD file update, resigning, etc.)
     * 
     * @param keyPair
     *            the AA key pair
     */
    public void setAAKeys(KeyPair keyPair) {
        this.aaPrivateKey = keyPair.getPrivate();
        DG_15_FILE dg15file = new DG_15_FILE(keyPair.getPublic());
        putFile(BasicService.EF_DG15, dg15file.getEncoded());
    }

    /**
     * 
     * @return the current AA private key
     */
    public PrivateKey getAAPrivateKey() {
        return aaPrivateKey;
    }

    /**
     * Sets the current AA private key.
     * 
     * @param key
     *            the AA private key.
     */
    public void setAAPrivateKey(PrivateKey key) {
        aaPrivateKey = key;
        updateSOIS();
    }

    /**
     * Sets the AA public key (alters DG15). Triggers all necessary changes
     * (COM/SOD file update, resigning, etc.)
     * 
     * @param key
     *            the AA public key
     */
    public void setAAPublicKey(PublicKey key) {
    	DG_15_FILE dg15file = new DG_15_FILE(key);
        putFile(BasicService.EF_DG15, dg15file.getEncoded());
    }

    /**
     * 
     * @return the current EAC private key
     */
    public PrivateKey getEACPrivateKey() {
        return eacPrivateKey;
    }

    /**
     * 
     * @return whether the driving license has EAC support
     */
    public boolean hasEAC() {
        return eacSupport;
    }

    /**
     * 
     * @return whether EAC was successfully performed.
     */
    public boolean wasEACPerformed() {
        return eacSuccess;
    }

    /**
     * 
     * @return the list of FIDs that are EAC protected on this card.
     */
    public List<Short> getEACFiles() {
        return eacFids;
    }

    /**
     * 
     * @return total length of all the files.
     */
    public int getTotalLength() {
        return totalLength;
    }

    /**
     * 
     * @return total number of files read in so far from the card
     *         (card).
     */
    public int getBytesRead() {
        return bytesRead;
    }

    /**
     * 
     * @return the list of all FIDS contained in this driving card.
     */
    public List<Short> getFileList() {
        List<Short> result = new ArrayList<Short>();
        result.addAll(fileLengths.keySet());
        return result;
    }

    /**
     * 
     * @return the stored key seed, null if missing
     */
    public byte[] getKeySeed() {
        return keySeed;
    }

    
    /**
     * Sets the key seed. 
     */
    public void setKeySeed(byte[] keySeed) {
        this.keySeed = keySeed;
    }

}

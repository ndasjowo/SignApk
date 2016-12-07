/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * How to Compile:
 * 1. javac SignApk.java
 * 2. Create MANIFEST.MF - ( echo Main-Class: nDasJoWo.SignApk >MANIFEST.MF )
 * 3. Create folder nDasJoWo
 * 4. Move all class(*.class) to folder nDasJoWo\signapk
 * 5. jar cvfm SignApk.jar MANIFEST.MF nDasJoWo\signapk\*.class
 * 6. java -jar SignApk.jar
 * Source original https://github.com/android/platform_build/blob/master/tools/signapk/SignApk.java
 * Referece: https://github.com/appium/sign/
 */

package nDasJoWo.signapk;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

//import sun.misc.BASE64Encoder;
//import sun.security.pkcs.ContentInfo;
//import sun.security.pkcs.PKCS7;
//import sun.security.pkcs.SignerInfo;
//import sun.security.x509.AlgorithmId;
//import sun.security.x509.X500Name;

// *CP bouncycastle
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

class SignApk
{
  private static final String CERT_SF_NAME = "META-INF/CERT.SF";
  private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";
  private static final String OTACERT_NAME = "META-INF/com/android/otacert";
  private static Provider sBouncyCastleProvider;
  private static Pattern stripPattern = Pattern.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");
  
  private static X509Certificate readPublicKey(File paramFile)
    throws IOException, GeneralSecurityException
  {
    FileInputStream localFileInputStream = new FileInputStream(paramFile);
    try {
      CertificateFactory localCertificateFactory = CertificateFactory.getInstance("X.509");
       return (X509Certificate)localCertificateFactory.generateCertificate(localFileInputStream);
    } finally {
       localFileInputStream.close();
    }
  }
  





  private static String readPassword(File paramFile)
  {
    System.out.print("Enter password for " + paramFile + " (password will not be hidden): ");
    System.out.flush();
    BufferedReader localBufferedReader = new BufferedReader(new InputStreamReader(System.in));
    try {
      return localBufferedReader.readLine();
    } catch (IOException localIOException) {}
    return null;
  }
  




  private static KeySpec decryptPrivateKey(byte[] paramArrayOfByte, File paramFile)
    throws GeneralSecurityException
  {
    EncryptedPrivateKeyInfo localEncryptedPrivateKeyInfo;
    



    try
    {
      localEncryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(paramArrayOfByte);
    }
    catch (IOException localIOException) {
      return null;
    }
    
    char[] arrayOfChar = readPassword(paramFile).toCharArray();
    
    SecretKeyFactory localSecretKeyFactory = SecretKeyFactory.getInstance(localEncryptedPrivateKeyInfo.getAlgName());
    SecretKey localSecretKey = localSecretKeyFactory.generateSecret(new PBEKeySpec(arrayOfChar));
    
    Cipher localCipher = Cipher.getInstance(localEncryptedPrivateKeyInfo.getAlgName());
    localCipher.init(2, localSecretKey, localEncryptedPrivateKeyInfo.getAlgParameters());
    try
    {
      return localEncryptedPrivateKeyInfo.getKeySpec(localCipher);
    } catch (InvalidKeySpecException localInvalidKeySpecException) {
      System.err.println("signapk: Password untuk " + paramFile + " mungkin salah.");
      throw localInvalidKeySpecException;
    }
  }
  

/** Read a PKCS 8 format private key. */
    private static PrivateKey readPrivateKey(File file)
            throws IOException, GeneralSecurityException {
        DataInputStream input = new DataInputStream(new FileInputStream(file));
        try {
            byte[] bytes = new byte[(int) file.length()];
            input.read(bytes);

            KeySpec spec = decryptPrivateKey(bytes, file);
            if (spec == null) {
                spec = new PKCS8EncodedKeySpec(bytes);
            }

            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (InvalidKeySpecException ex) {
                return KeyFactory.getInstance("DSA").generatePrivate(spec);
            }
        } finally {
            input.close();
        }
    }
	
  private static Manifest addDigestsToManifest(JarFile paramJarFile)
    throws IOException, GeneralSecurityException
  {
    Manifest localManifest1 = paramJarFile.getManifest();
    Manifest localManifest2 = new Manifest();
    Attributes localAttributes1 = localManifest2.getMainAttributes();
    if (localManifest1 != null) {
      localAttributes1.putAll(localManifest1.getMainAttributes());
    } else {
      localAttributes1.putValue("Manifest-Version", "1.0");
      localAttributes1.putValue("Created-By", "1.0 (nDasJoWo)");
    }
    
    MessageDigest localMessageDigest = MessageDigest.getInstance("SHA1");
    byte[] arrayOfByte = new byte[4096];


    TreeMap localTreeMap = new TreeMap();
    
    for (Object localObject = paramJarFile.entries(); ((Enumeration)localObject).hasMoreElements();) {
      JarEntry localJarEntry = (JarEntry)((Enumeration)localObject).nextElement();
      localTreeMap.put(localJarEntry.getName(), localJarEntry);
    }
    JarEntry localJarEntry;
    for (Object localObject = localTreeMap.values().iterator(); ((Iterator)localObject).hasNext();)
	{ localJarEntry = (JarEntry)((Iterator)localObject).next();
      String str = localJarEntry.getName();
      if ((!localJarEntry.isDirectory()) && (!str.equals("META-INF/MANIFEST.MF")) && (!str.equals("META-INF/CERT.SF")) && (!str.equals("META-INF/CERT.RSA")) && (!str.equals("META-INF/com/android/otacert")) && ((stripPattern == null) || (!stripPattern.matcher(str).matches())))
      {



        InputStream localInputStream = paramJarFile.getInputStream(localJarEntry);
        int i; while ((i = localInputStream.read(arrayOfByte)) > 0) {
          localMessageDigest.update(arrayOfByte, 0, i);
        }
        
        Attributes localAttributes2 = null;
        if (localManifest1 != null) localAttributes2 = localManifest1.getAttributes(str);
        localAttributes2 = localAttributes2 != null ? new Attributes(localAttributes2) : new Attributes();
        localAttributes2.putValue("SHA1-Digest", new String(Base64.encode(localMessageDigest.digest()), "ASCII"));
        
        localManifest2.getEntries().put(str, localAttributes2);
      }
    }
    
    return localManifest2;
  }
  


  private static void addOtacert(JarOutputStream paramJarOutputStream, File paramFile, long paramLong, Manifest paramManifest)
    throws IOException, GeneralSecurityException
  {
    MessageDigest localMessageDigest = MessageDigest.getInstance("SHA1");
    
    JarEntry localJarEntry = new JarEntry("META-INF/com/android/otacert");
    localJarEntry.setTime(paramLong);
    paramJarOutputStream.putNextEntry(localJarEntry);
    FileInputStream localFileInputStream = new FileInputStream(paramFile);
    byte[] arrayOfByte = new byte[4096];
    int i;
    while ((i = localFileInputStream.read(arrayOfByte)) != -1) {
      paramJarOutputStream.write(arrayOfByte, 0, i);
      localMessageDigest.update(arrayOfByte, 0, i);
    }
    localFileInputStream.close();
    
    Attributes localAttributes = new Attributes();
    localAttributes.putValue("SHA1-Digest", new String(Base64.encode(localMessageDigest.digest()), "ASCII"));
    
    paramManifest.getEntries().put("META-INF/com/android/otacert", localAttributes);
  }
  

  private static class CountOutputStream extends FilterOutputStream {
    private int mCount;
    
    public CountOutputStream(OutputStream paramOutputStream) {
      super(paramOutputStream);
      this.mCount = 0;
    }
    
    public void write(int paramInt) throws IOException {
      super.write(paramInt);
      this.mCount += 1;
    }
    
    public void write(byte[] paramArrayOfByte, int paramInt1, int paramInt2) throws IOException {
      super.write(paramArrayOfByte, paramInt1, paramInt2);
      this.mCount += paramInt2;
    }
    
    public int size() {
      return this.mCount;
    }
  }


  private static void writeSignatureFile(Manifest paramManifest, OutputStream paramOutputStream)
    throws IOException, GeneralSecurityException
  {
    Manifest localManifest = new Manifest();
    Attributes localAttributes = localManifest.getMainAttributes();
    localAttributes.putValue("Signature-Version", "1.0");
    localAttributes.putValue("Created-By", "1.0 (nDasJoWo)");
    
    MessageDigest localMessageDigest = MessageDigest.getInstance("SHA1");
    PrintStream localPrintStream = new PrintStream(new DigestOutputStream(new ByteArrayOutputStream(), localMessageDigest), true, "UTF-8");
    



    paramManifest.write(localPrintStream);
    localPrintStream.flush();
    localAttributes.putValue("SHA1-Digest-Manifest", new String(Base64.encode(localMessageDigest.digest()), "ASCII"));
    

    Map localMap = paramManifest.getEntries();
    for (Object localObject1 = localMap.entrySet().iterator(); ((Iterator)localObject1).hasNext();) 
    { Map.Entry localEntry1 = (Map.Entry)((Iterator)localObject1).next();
      
      localPrintStream.print("Name: " + (String)localEntry1.getKey() + "\r\n");
      for (Object localObject2 = ((Attributes)localEntry1.getValue()).entrySet().iterator(); ((Iterator)localObject2).hasNext();) 
      { Map.Entry localEntry2 = (Map.Entry)((Iterator)localObject2).next();
        localPrintStream.print(localEntry2.getKey() + ": " + localEntry2.getValue() + "\r\n");
      }
      localPrintStream.print("\r\n");
      localPrintStream.flush();
      
      Attributes localObject2 = new Attributes();
      ((Attributes)localObject2).putValue("SHA1-Digest", new String(Base64.encode(localMessageDigest.digest()), "ASCII"));
      
      localManifest.getEntries().put((String)localEntry1.getKey(), localObject2);
    }
    
    Object localObject1 = new CountOutputStream(paramOutputStream);
    localManifest.write((OutputStream)localObject1);
    




    if (((CountOutputStream)localObject1).size() % 1024 == 0) {
      ((CountOutputStream)localObject1).write(13);
      ((CountOutputStream)localObject1).write(10);
    }
  }
  





  private static void writeSignatureBlock(CMSTypedData paramCMSTypedData, X509Certificate paramX509Certificate, PrivateKey paramPrivateKey, OutputStream paramOutputStream)
    throws IOException, CertificateEncodingException, OperatorCreationException, CMSException
  {
    ArrayList localArrayList = new ArrayList(1);
    localArrayList.add(paramX509Certificate);
    JcaCertStore localJcaCertStore = new JcaCertStore(localArrayList);
    
    CMSSignedDataGenerator localCMSSignedDataGenerator = new CMSSignedDataGenerator();
    ContentSigner localContentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(sBouncyCastleProvider).build(paramPrivateKey);

    localCMSSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(sBouncyCastleProvider).build()).setDirectSignature(true).build(localContentSigner, paramX509Certificate));

    localCMSSignedDataGenerator.addCertificates(localJcaCertStore);
    CMSSignedData localCMSSignedData = localCMSSignedDataGenerator.generate(paramCMSTypedData, false);
    
    ASN1InputStream localASN1InputStream = new ASN1InputStream(localCMSSignedData.getEncoded());
    DEROutputStream localDEROutputStream = new DEROutputStream(paramOutputStream);
    localDEROutputStream.writeObject(localASN1InputStream.readObject());
  }
  





  private static void copyFiles(Manifest paramManifest, JarFile paramJarFile, JarOutputStream paramJarOutputStream, long paramLong)
    throws IOException
  {
     byte[] arrayOfByte = new byte[4096];
    

     Map<String, Attributes> localMap = paramManifest.getEntries();
     ArrayList<String> localArrayList = new ArrayList<String>(localMap.keySet());
     Collections.sort(localArrayList);
     for (String str : localArrayList) {
       JarEntry localJarEntry1 = paramJarFile.getJarEntry(str);
       JarEntry localJarEntry2 = null;
       if (localJarEntry1.getMethod() == 0)
      {
         localJarEntry2 = new JarEntry(localJarEntry1);
      }
      else {
         localJarEntry2 = new JarEntry(str);
      }
       localJarEntry2.setTime(paramLong);
       paramJarOutputStream.putNextEntry(localJarEntry2);
      
       InputStream localInputStream = paramJarFile.getInputStream(localJarEntry1);
       int i; while ((i = localInputStream.read(arrayOfByte)) > 0) {
         paramJarOutputStream.write(arrayOfByte, 0, i);
      }
       paramJarOutputStream.flush();
    }
  }
  
  private static class WholeFileSignerOutputStream extends FilterOutputStream {
    private boolean closing = false;
    private ByteArrayOutputStream footer = new ByteArrayOutputStream();
    private OutputStream tee;
    
    public WholeFileSignerOutputStream(OutputStream paramOutputStream1, OutputStream paramOutputStream2) {
      super(paramOutputStream1);
      this.tee = paramOutputStream2;
    }
    
    public void notifyClosing() {
      this.closing = true;
    }
    
    public void finish() throws IOException {
      this.closing = false;
      
      byte[] arrayOfByte = this.footer.toByteArray();
      if (arrayOfByte.length < 2)
        throw new IOException("Less than two bytes written to footer");
      write(arrayOfByte, 0, arrayOfByte.length - 2);
    }
    
    public byte[] getTail() {
      return this.footer.toByteArray();
    }
    
    public void write(byte[] paramArrayOfByte) throws IOException {
      write(paramArrayOfByte, 0, paramArrayOfByte.length);
    }
    
    public void write(byte[] paramArrayOfByte, int paramInt1, int paramInt2) throws IOException {
      if (this.closing)
      {
        this.footer.write(paramArrayOfByte, paramInt1, paramInt2);
      }
      else
      {
        this.out.write(paramArrayOfByte, paramInt1, paramInt2);
        this.tee.write(paramArrayOfByte, paramInt1, paramInt2);
      }
    }
    
    public void write(int paramInt) throws IOException {
      if (this.closing)
      {
        this.footer.write(paramInt);
      }
      else
      {
        this.out.write(paramInt);
        this.tee.write(paramInt);
      }
    }
  }
  
  private static class CMSSigner implements CMSTypedData {
    private JarFile inputJar;
    private File publicKeyFile;
    private X509Certificate publicKey;
    private PrivateKey privateKey;
    private String outputFile;
    private OutputStream outputStream;
    private final ASN1ObjectIdentifier type;
    private SignApk.WholeFileSignerOutputStream signer;
    
    public CMSSigner(JarFile paramJarFile, File paramFile, X509Certificate paramX509Certificate, PrivateKey paramPrivateKey, OutputStream paramOutputStream) {
      this.inputJar = paramJarFile;
      this.publicKeyFile = paramFile;
      this.publicKey = paramX509Certificate;
      this.privateKey = paramPrivateKey;
      this.outputStream = paramOutputStream;
      this.type = new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId());
    }
    
    public Object getContent() {
      throw new UnsupportedOperationException();
    }
    
    public ASN1ObjectIdentifier getContentType() {
      return this.type;
    }
    
    public void write(OutputStream paramOutputStream) throws IOException {
      try {
        this.signer = new SignApk.WholeFileSignerOutputStream(paramOutputStream, this.outputStream);
        JarOutputStream localJarOutputStream = new JarOutputStream(this.signer);
        
        Manifest localManifest = SignApk.addDigestsToManifest(this.inputJar);
        SignApk.signFile(localManifest, this.inputJar, this.publicKeyFile, this.publicKey, this.privateKey, localJarOutputStream);
        
        long l = this.publicKey.getNotBefore().getTime() + 3600000L;
        SignApk.addOtacert(localJarOutputStream, this.publicKeyFile, l, localManifest);
        
        this.signer.notifyClosing();
        localJarOutputStream.close();
        this.signer.finish();
      }
      catch (Exception localException) {
        throw new IOException(localException);
      }
    }
    

    public void writeSignatureBlock(ByteArrayOutputStream paramByteArrayOutputStream)
      throws IOException, CertificateEncodingException, OperatorCreationException, CMSException
    {
      SignApk.writeSignatureBlock(this, this.publicKey, this.privateKey, paramByteArrayOutputStream);
    }
    
    public SignApk.WholeFileSignerOutputStream getSigner() {
      return this.signer;
    }
  }
  
  public static void signWholeFile(JarFile paramJarFile, File paramFile, X509Certificate paramX509Certificate, PrivateKey paramPrivateKey, OutputStream paramOutputStream) throws Exception {
    CMSSigner localCMSSigner = new CMSSigner(paramJarFile, paramFile, paramX509Certificate, paramPrivateKey, paramOutputStream);
    
    ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();

    byte[] arrayOfByte1 = "signed by nDasJoWo".getBytes("UTF-8");
    localByteArrayOutputStream.write(arrayOfByte1);
    localByteArrayOutputStream.write(0);
    
    localCMSSigner.writeSignatureBlock(localByteArrayOutputStream);
    
    byte[] arrayOfByte2 = localCMSSigner.getSigner().getTail();
    



    if ((arrayOfByte2[(arrayOfByte2.length - 22)] != 80) || (arrayOfByte2[(arrayOfByte2.length - 21)] != 75) || (arrayOfByte2[(arrayOfByte2.length - 20)] != 5) || (arrayOfByte2[(arrayOfByte2.length - 19)] != 6))
    {
      throw new IllegalArgumentException("data zip sudah memiliki komentar");
    }
    
    int i = localByteArrayOutputStream.size() + 6;
    if (i > 65535) {
      throw new IllegalArgumentException("signature terlalu panjang untuk komentar file ZIP");
    }
    
    int j = i - arrayOfByte1.length - 1;
    localByteArrayOutputStream.write(j & 0xFF);
    localByteArrayOutputStream.write(j >> 8 & 0xFF);

    localByteArrayOutputStream.write(255);
    localByteArrayOutputStream.write(255);
    localByteArrayOutputStream.write(i & 0xFF);
    localByteArrayOutputStream.write(i >> 8 & 0xFF);
    localByteArrayOutputStream.flush();


    byte[] arrayOfByte3 = localByteArrayOutputStream.toByteArray();
    for (int k = 0; k < arrayOfByte3.length - 3; k++) {
      if ((arrayOfByte3[k] == 80) && (arrayOfByte3[(k + 1)] == 75) && (arrayOfByte3[(k + 2)] == 5) && (arrayOfByte3[(k + 3)] == 6)) {
        throw new IllegalArgumentException("found spurious EOCD header at " + k);
      }
    }
    
    paramOutputStream.write(i & 0xFF);
    paramOutputStream.write(i >> 8 & 0xFF);
    localByteArrayOutputStream.writeTo(paramOutputStream);
  }
  
  public static void signFile(Manifest paramManifest, JarFile paramJarFile, File paramFile, X509Certificate paramX509Certificate, PrivateKey paramPrivateKey, JarOutputStream paramJarOutputStream) throws Exception
  {
    long l = paramX509Certificate.getNotBefore().getTime() + 3600000L;

    copyFiles(paramManifest, paramJarFile, paramJarOutputStream, l);

    JarEntry localJarEntry = new JarEntry("META-INF/MANIFEST.MF");
    localJarEntry.setTime(l);
    paramJarOutputStream.putNextEntry(localJarEntry);
    paramManifest.write(paramJarOutputStream);

    localJarEntry = new JarEntry("META-INF/CERT.SF");
    localJarEntry.setTime(l);
    paramJarOutputStream.putNextEntry(localJarEntry);
    ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
    writeSignatureFile(paramManifest, localByteArrayOutputStream);
    byte[] arrayOfByte = localByteArrayOutputStream.toByteArray();
    paramJarOutputStream.write(arrayOfByte);

    localJarEntry = new JarEntry("META-INF/CERT.RSA");
    localJarEntry.setTime(l);
    paramJarOutputStream.putNextEntry(localJarEntry);
    writeSignatureBlock(new CMSProcessableByteArray(arrayOfByte), paramX509Certificate, paramPrivateKey, paramJarOutputStream);
  }
  
  public static void main(String[] paramArrayOfString)
  {
    if ((paramArrayOfString.length != 4) && (paramArrayOfString.length != 5)) {
      System.err.println("Gunakan perintah: java -jar signapk.jar [-w] publickey.x509[.pem] privatekey.pk8 [Sumber_File.zip/apk] [Hasil_File.zip/apk]");

      System.exit(2);
    }
    
    sBouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(sBouncyCastleProvider);
    
    int i = 0;
    int j = 0;
    if (paramArrayOfString[0].equals("-w")) {
      i = 1;
      j = 1;
    }
    
    JarFile localJarFile = null;
    FileOutputStream localFileOutputStream = null;
    try
    {
      File localFile = new File(paramArrayOfString[(j + 0)]);
      X509Certificate localX509Certificate = readPublicKey(localFile);
      
      PrivateKey localPrivateKey = readPrivateKey(new File(paramArrayOfString[(j + 1)]));
      localJarFile = new JarFile(new File(paramArrayOfString[(j + 2)]), false);
      
      localFileOutputStream = new FileOutputStream(paramArrayOfString[(j + 3)]);
      
      if (i != 0) {
        signWholeFile(localJarFile, localFile, localX509Certificate, localPrivateKey, localFileOutputStream);
      }
      else {
        JarOutputStream localJarOutputStream = new JarOutputStream(localFileOutputStream);

        localJarOutputStream.setLevel(9);
        
        signFile(addDigestsToManifest(localJarFile), localJarFile, localFile, localX509Certificate, localPrivateKey, localJarOutputStream);
        localJarOutputStream.close();
      }
      return;
    } catch (Exception localException) { localException.printStackTrace();
      System.exit(1);
    } finally {
      try {
        if (localJarFile != null) localJarFile.close();
        if (localFileOutputStream != null) localFileOutputStream.close();
      } catch (IOException localIOException3) {
        localIOException3.printStackTrace();
        System.exit(1);
      }
    }
  }
}

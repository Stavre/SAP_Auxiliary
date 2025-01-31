package ism.stavre.marian;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void decrypt(
            String filename,
            String outputFile) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {


        //IV the cipher file at the beginning

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File outFile = new File(outputFile);
        if(!outFile.exists()) {
            outFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outFile);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        //getting the IV from the file
        byte[] IV = new byte[cipher.getBlockSize()];
        for (int i = 0; i < IV.length; i++){
            IV[i] = 0;
        }
        IV[10] = (byte) 0b1111_1111;

//        fis.read(IV);
        //
        //The byte with index 10 from left to right has all bits 1. The others are all 0
        SecretKeySpec key = new SecretKeySpec("userfilepass%3#2".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }


    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
//        result.append("0x");
        for(byte b : value) {
            result.append(String.format("%02X", Byte.valueOf(b)));
            ;
        }
        return result.toString();
    }


    public static byte[] getFileMessageDigest(File file, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }

        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);

        MessageDigest ms = MessageDigest.getInstance(algorithm, provider);

        byte[] buffer = new byte[8];
        int noBytesFromFile = 0;

        while((noBytesFromFile = bis.read(buffer)) != -1) {
            ms.update(buffer, 0, noBytesFromFile);
        }

        bis.close();

        return ms.digest();
    }

    public static byte[] getStringMessageDigest(String text, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {

        //hashing a string
        MessageDigest md = MessageDigest.getInstance(algorithm, provider);
        //compute the hash in one step - the input is small enough
        return md.digest(text.getBytes());
    }

    public static String encodeBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decodeBase64(String text){
        return Base64.getDecoder().decode(text);
    }


    public static byte[] getPBKDF(
            String userPassword,
            String algorithm,
            String salt,
            int noIterations
    ) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory pbkdf =
                SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec pbkdfSpecifications =
                new PBEKeySpec(
                        userPassword.toCharArray(),
                        salt.getBytes(),
                        noIterations,256);
        SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
        return secretKey.getEncoded();

    }

    public static List<File> listAllFiles(String folderPath){
        File folder = new File(folderPath);
        if (!folder.exists()){
            throw new RuntimeException("Path does not exist");
        }

        if (!folder.isDirectory()){
            throw new RuntimeException("This path is not a folder");
        }
			//print location content
			File[] items = folder.listFiles();
        if (items == null){
            throw new RuntimeException("no files found");
        }
        return Arrays.stream(items).filter(File::exists).filter(File::isFile).toList();

    }


    public static byte[] getHMAC(
            String fileName, String algorithm, String password)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        Mac hmac = Mac.getInstance(algorithm);
        SecretKeySpec key = new SecretKeySpec(
                password.getBytes(), algorithm);
        hmac.init(key);

        //read the file and process it
        File inputFile = new File(fileName);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("File is missing");
        }
        FileInputStream fis = new FileInputStream(inputFile);
        BufferedInputStream bis = new BufferedInputStream(fis);

        byte[] buffer = new byte[8];
        while(true) {
            int noBytes = bis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            hmac.update(buffer, 0, noBytes);
        }

        fis.close();

        return hmac.doFinal();
    }

    public static byte[] getHMAC(
            String fileName, String algorithm, byte[] password)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        Mac hmac = Mac.getInstance(algorithm);
        SecretKeySpec key = new SecretKeySpec(
                password, algorithm);
        hmac.init(key);

        //read the file and process it
        File inputFile = new File(fileName);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("File is missing");
        }
        FileInputStream fis = new FileInputStream(inputFile);
        BufferedInputStream bis = new BufferedInputStream(fis);

        byte[] buffer = new byte[8];
        while(true) {
            int noBytes = bis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            hmac.update(buffer, 0, noBytes);
        }

        fis.close();

        return hmac.doFinal();
    }


    public static KeyStore getKeyStore(
            String ksFileName, String ksPassword) throws KeyStoreException, NoSuchAlgorithmException,  IOException, CertificateException {
        File ksFile = new File(ksFileName);
        if(!ksFile.exists()) {
            throw new UnsupportedOperationException("KS file missin");
        }
        FileInputStream fis = new FileInputStream(ksFile);

        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(fis, ksPassword.toCharArray());
        fis.close();
        return ks;
    }

    public static void printKSContent(KeyStore ks) throws KeyStoreException {
        if(ks != null) {
            System.out.println("Key Store content: ");

            Enumeration<String> items = ks.aliases();

            while(items.hasMoreElements()) {
                String item = items.nextElement();
                System.out.println("Item: " + item);
                if(ks.isKeyEntry(item)) {
                    System.out.println("\t - is a key pair");
                }
                if(ks.isCertificateEntry(item)) {
                    System.out.println("\t - is a public key");
                }
            }
        }
    }

    public static PublicKey getPublicKey(KeyStore ks, String alias) throws KeyStoreException {
        if(ks != null && ks.containsAlias(alias)) {
            return ks.getCertificate(alias).getPublicKey();
        } else {
            throw new UnsupportedOperationException("No KS or no alias");
        }
    }

    public static PrivateKey getPrivateKey(KeyStore ks, String alias, String ksPass
    ) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        if(ks != null && ks.containsAlias(alias) &&
                ks.isKeyEntry(alias)) {
            return (PrivateKey) ks.getKey(alias, ksPass.toCharArray());
        }
        else {
            throw new UnsupportedOperationException("KS issue");
        }
    }

    public static PublicKey getPublicFromX509(String filename) throws FileNotFoundException, CertificateException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        FileInputStream fis = new FileInputStream(file);
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
        X509Certificate cert =
                (X509Certificate) factory.generateCertificate(fis);
        return cert.getPublicKey();
    }

    public static byte[] encryptRSA(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] decryptRSA(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] getSymmetricRandomKey(
            int noBits, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(algorithm);
        keyGenerator.init(noBits);
        return keyGenerator.generateKey().getEncoded();
    }

    public static byte[] getDigitalSignature(
            String file, PrivateKey privateKey, String signatureAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        File inputFile = new File(file);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("No FILE");
        }
        FileInputStream fis = new FileInputStream(inputFile);
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);

        //process the entire file on one round
        byte[] buffer = fis.readAllBytes();
        signature.update(buffer);

        fis.close();

        //TO DO: when the file is processed in blocks

        return signature.sign();
    }
    public static boolean isSignatureValid(
            String filename, byte[] signature, PublicKey publicKey, String signingAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
// "SHA1withRSA"
        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("No FILE");
        }
        FileInputStream fis = new FileInputStream(inputFile);

        Signature sign = Signature.getInstance(signingAlgorithm);
        sign.initVerify(publicKey);

        byte[] buffer = fis.readAllBytes();
        fis.close();

        sign.update(buffer);
        return sign.verify(signature);
    }
//

    public static void encryptSymmetrical(
            String inputFile,
            String outputFile,
            String usedCipher,
            String mode,
            String padding,
            byte[] IV,
            byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        /**
         * usedCipher: DES or AES
         * mode: CBC, ECB, CTS, CTR
         * padding: PKCS5Padding or NoPadding
         * */

        File inputF = new File(inputFile);
        if(!inputF.exists()) {
            throw new UnsupportedOperationException("No FILE");
        }
        File outputF = new File(outputFile);
        if(!outputF.exists()) {
            outputF.createNewFile();
        }
        FileInputStream fis = new FileInputStream(inputF);
        FileOutputStream fos = new FileOutputStream(outputF);

        Cipher cipher = Cipher.getInstance("%s/%s/%s".formatted(usedCipher, mode, padding));
        SecretKeySpec keySpec = new SecretKeySpec(key, usedCipher);

        byte[] buffer = new byte[cipher.getBlockSize()];

        //IV values:
        //1. hard coded known value
        //2. known value or any value stored
        //	in the ciphertext as the 1st block

        //option 2
        //IV has the 3rd byte with all bits 1
//        byte[] IV = new byte[cipher.getBlockSize()];
//        IV[2] = (byte) 0xFF;

        if (IV != null){
            //write IV into file
            fos.write(IV);
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec,ivSpec);
        }
        else{
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }




        while(true) {
            int noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] output = cipher.update(buffer, 0, noBytes);
            fos.write(output);
        }

        byte[] output = cipher.doFinal();
        fos.write(output);

        fis.close();
        fos.close();

    }

    public static void decryptSymmetrical(
            String inputFile,
            String outputFile,
            String usedCipher,
            String mode,
            String padding,
            Boolean useIV,
            byte[] key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        File inputF = new File(inputFile);
        if(!inputF.exists()) {
            throw new UnsupportedOperationException("No File");
        }
        File outputF = new File(outputFile);
        if(!outputF.exists()){
            outputF.createNewFile();
        }

        FileInputStream fis  = new FileInputStream(inputF);
        FileOutputStream fos = new FileOutputStream(outputF);

        Cipher cipher = Cipher.getInstance("%s/%s/%s".formatted(usedCipher, mode, padding));

        if (useIV){
            //read IV
            byte[] IV = new byte[cipher.getBlockSize()];
            fis.read(IV);


            SecretKeySpec keySpec = new SecretKeySpec(key, usedCipher);
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.DECRYPT_MODE, keySpec,ivSpec);
        }
        else{
            SecretKeySpec keySpec = new SecretKeySpec(key, usedCipher);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }



        byte[] buffer = new byte[cipher.getBlockSize()];
        while(true) {
            int noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] output = cipher.update(buffer,0,noBytes);
            fos.write(output);
        }
        byte[] output = cipher.doFinal();
        fos.write(output);

        fis.close();
        fos.close();

    }


    public static void writeBytesToFile(String fileName, byte[] content) throws IOException {
        File outputF = new File(fileName);
        if(!outputF.exists()) {
            outputF.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(outputF);
        fos.write(content);

        fos.close();
    }

    public static void writeStringToFile(String fileName, String content) throws IOException {
        File outputF = new File(fileName);
        FileWriter fileWriter = new FileWriter(outputF);
        if(!outputF.exists()) {
            outputF.createNewFile();
        }
        BufferedWriter fos = new BufferedWriter(fileWriter);
        fos.write(content);

        fos.close();
        fileWriter.close();
    }

    public static byte[] readBytesFromFile(String fileName) throws IOException {
        File inputF = new File(fileName);
        if(!inputF.exists()) {
            throw new RuntimeException("File %s does not exist".formatted(fileName));
        }
        FileInputStream fis = new FileInputStream(inputF);
        byte[] content = fis.readAllBytes();

        fis.close();

        return content;
    }

    public static void main(String[] args) {
        //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
        // to see how IntelliJ IDEA suggests fixing it.
        System.out.printf("Hello and welcome!");

        for (int i = 1; i <= 5; i++) {
            //TIP Press <shortcut actionId="Debug"/> to start debugging your code. We have set one <icon src="AllIcons.Debugger.Db_set_breakpoint"/> breakpoint
            // for you, but you can always add more by pressing <shortcut actionId="ToggleLineBreakpoint"/>.
            System.out.println("i = " + i);
        }
    }
}


//        keytool.exe -genkey -keyalg RSA -alias ismkey1 -keypass passism1 -storepass passks -keystore ismkeystore.ks -dname "cn=ISM, ou=ISM, o=IT&C Security Master, c=RO"
//
//        keytool.exe -genkey -keyalg RSA -alias ismkey2 -keypass passism2 -storepass passks -keystore ismkeystore.ks -dname "cn=ISM, ou=ISM, o=IT&C Security Master, c=RO"
//
//        keytool.exe -export -alias ismkey1 -file ISMCertificateX509.cer -keystore ismkeystore.ks -storepass passks



//        Scanner scanner = new Scanner(new File("sample.txt"));
//
//			while (scanner.hasNextLine()) {
//        System.out.println(scanner.nextLine());
//        }
//
//        scanner.close();
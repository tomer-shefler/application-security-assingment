package crypto;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import javax.crypto.*;
import java.util.Base64;


public class Crypto {
    static String usage = "crypto CONF INPUT_DATA";

    private static KeyPair getKeyPair(KeyStore keyStore, String alias, String password) throws Exception {
        Key key = keyStore.getKey(alias, password.toCharArray());
        if ((key instanceof PrivateKey)) {
            return null;
        }

        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ftpkey");
        return new KeyPair(cert.getPublicKey(), (PrivateKey)key);
    }

    private static KeyStore getKeyStore(String path, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis, password.toCharArray());
        return keyStore;
    }

    private static boolean verifySignature(KeyPair kp, byte[] data, byte[] signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        try {
            dsa.initVerify(kp.getPublic());
            dsa.update(data);
            return dsa.verify(signature); 
        } catch (InvalidKeyException e) {
            System.out.println("Verify signature: invalid key");
            return false;
        } catch (SignatureException e) {
            System.out.println("Verify signature: signature exeption");
            return false;
        }
    }

    private static byte[] sign(KeyPair kp, byte[] data) throws Exception {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(kp.getPrivate());
        dsa.update(data);
        return dsa.sign();
    }

    private static byte[] decryptData(KeyPair kp, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        return cipher.doFinal(data);
    }

    private static byte[] encryptData(KeyPair kp, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        return cipher.doFinal(data);
    }

    public static byte[] readFile(String path) throws Exception {
        InputStream in = new FileInputStream(path);
        long fileSize = new File(path).length();
        byte[] data = new byte[(int) fileSize];
        in.read(data);
        return data;
    }

    public static void writeFile(String path, byte[] data) throws Exception {
        OutputStream outputStream = new FileOutputStream(path);
        outputStream.write(data);
    }

    public static byte[] encrypt(KeyPair kp, String inputFile) throws Exception {
        byte[] plainData = readFile(inputFile);
        byte[] encryptedData = encryptData(kp, plainData);
        byte[] signature = sign(kp, encryptedData);        
        writeFile(inputFile + ".cipher", encryptedData);
        return signature;
    }

    public static void decrypt(KeyPair kp, String inputFile, byte[] signature) throws Exception {
        byte[] cryptData = readFile(inputFile);
        if (!verifySignature(kp, cryptData, signature)) {
            System.out.println("Unable to dectypt file: invalid signature");
            return;
        }
        byte[] decryptedData = decryptData(kp, cryptData);
        writeFile(inputFile + ".plain", decryptedData);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Invalid arguments\n Usage: " + usage);
            return;
        }

        Conf conf = new Conf();
        String confPath = args[0];
        conf.load(confPath);
        String inputPath = args[1];
        KeyStore ks = getKeyStore(conf.keyStorePath, conf.password);
        KeyPair keyPair = getKeyPair(ks, conf.alias, conf.password);
        
        if (keyPair == null) {
            System.out.println("Keypair is null");
            return;
        }

        if (conf.mode) {
            byte[] signature = encrypt(keyPair, inputPath);
            String base64Signatue = Base64.getEncoder().encodeToString(signature);
            conf.store(confPath + ".decryptor", base64Signatue);
        } else {
            byte[] signature = Base64.getDecoder().decode(conf.signature);
            decrypt(keyPair, inputPath, signature);
        }
    }
    

}

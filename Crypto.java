import java.io.*;
import java.security.*;
import java.security.cert.*;
import javax.crypto.*;
import java.util.Properties;


public class Conf {
    boolean mode;
    String password;
    String alias;
    String keyStorePath;
    String signature;
    Properties prop

    public Conf() {

    }

    public void store(String path, String signature) {
        OutputStream output = new FileOutputStream(path);
        this.prop.setPropery("signature", signature);
        this.prop.store(output);
    }

    public void load(String path) {
        InputStream input = new FileInputStream(path);
        this.prop = new Properties();
        this.prop.load(input);
        this.mode = this.prop.getProperty("mode") == "encrypt";
        this.password = this.prop.getProperty("password");
        this.alias = prop.getProperty("alias");
        this.keyStorePath = this.prop.getProperty("keystore");

        String signature = this.prop.getProperty("signature");
        // Signature is optional, and required only on decrypt mode.
        if (signature != null) {
            this.signature = signature;
        }
    }
}

public class Crypto {
    static String usage = "crypto CONF INPUT_DATA";

    private static void getProperties(path) {
    }

    private static KeyPair getKeyPair(KeyStore keyStore, String alias, String password) {
        Key key = keyStore.getKey(alias, password.toCharArray());
        if ((key instanceof PrivateKey)) {
            return null;
        }

        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ftpkey");
        return new KeyPair(cert.getPublicKey(), (PrivateKey)key);
    }

    private static KeyStore getKeyStore(String path, String password) {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis, password.toCharArray());
        return keyStore;
    }

    private static boolean verifySignature(KeyPair kp, byte[] data, byte[] signature) {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initVerify(kp.getPublic());
        dsa.update(data);
        return dsa.verify(signature); 
    }

    private static byte[] sign(KeyPair kp, byte[] data) {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(kp.getPrivate());
        dsa.update(data);
        return dsa.sign();
    }

    private static byte[] decryptData(KeyPair kp, byte[] data) {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        return cipher.doFinal(data);
    }

    private static byte[] encryptData(KeyPair kp, byte[] data) {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        return cipher.doFinal(data);
    }

    public static byte[] readFile(String path) {
        InputStream in = new FileInputStream(path);
        long fileSize = new File(path).length();
        byte[] data = new byte[(int) fileSize];
        in.read(data);
        return data;
    }

    public static void writeFile(String path, byte[] data) {
        OutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(data);
    }

    public static byte[] encrypt(KeyPair kp, String inputFile) {
        byte[] plain_data = readFile(inputFile);
        byte[] signature = sign(kp, plain_data);        
        byte[] encrypted_data = encrypt_data(kp, plain_data);
        writeFile(inputFile + ".cipher", encrypted_data);
        return signature;
    }

    public static void decrypt(KeyPair kp, String inputFile, byte[] signature) {
        byte[] crypt_data = readFile(inputFile);
        if (!verify_signature(kp, crypt_data, signature)) {
            System.out.println("Unable to dectypt file: invalid signature");
            return
        }
        byte[] decrypted_data = decrypt_data(kp, crypt_data);
        writeFile(inputFile + ".plain", decrypted_data)
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Invalid arguments\n Usage: " + usage);
        }

        Conf conf = new Conf();
        String confPath = args[1];
        conf.load(confPath);
        String inputPath = args[2];
        KeyStore ks = getKeyStore(conf.password, conf.keyStorePath);
        KeyPair keyPair = getKeyPair(ks, conf.alias, conf.password);
        
        if (conf.mode) {
            String signature = encrypt(keyPair, inputPath);
            conf.store(confPath + ".decryptor", signature);
        } else {
            decrypt(keyPair, inputPath, conf.signature);
        }
    }
    

}

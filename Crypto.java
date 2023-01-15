import java.io.*;
import java.security.*;
import java.security.cert.*;
import javax.crypto.*;

public class Crypto {
    static String usage = "crypto <encrypt/decrypt> KEYSTORE PASSWORD ALIAS INPUT_DATA";

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

    private static boolean verify_signature(KeyPair kp, byte[] data, byte[] signature) {
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

    private static byte[] decrypt_data(KeyPair kp, byte[] data) {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        return cipher.doFinal(data);
    }

    private static byte[] encrypt_data(KeyPair kp, byte[] data) {
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

    public static void encrypt(KeyPair kp, String inputFile) {
        byte[] plain_data = readFile(inputFile);
        byte[] signeture = sign(kp, plain_data);        
        byte[] encrypted_data = encrypt_data(kp, plain_data);
    }
    

    public static void decrypt(KeyPair kp, String inputFile, byte[] signature) {
        byte[] crypt_data = readFile(inputFile);
        if (verify_signature(kp, crypt_data, signature)) {
            byte[] decrypted_data = decrypt_data(kp, crypt_data);
        } else {
            System.out.println("Unable to dectypt file: invalid signature");
        }
    }

    public static void main(String[] args) {
        if (args.length != 6) {
            System.out.println("Invalid arguments\n Usage: " + usage);
        }

        boolean encrypt_mode = args[1] == "encrypt";
        String password = args[2];
        String keyStorePath = args[3];
        String alias = args[4];
        KeyStore ks = getKeyStore(password, args[3]);
        KeyPair keyPair = getKeyPair(ks, alias, password);
        String path = args[5];
        byte[] signature;

        if (encrypt_mode) {
            encrypt(keyPair, path);
        } else {
            decrypt(keyPair, path, signature);
        }
    }
    

}

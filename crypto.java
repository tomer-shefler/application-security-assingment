import java.io.*;
import java.security.*;

public class Crypto {
    const String usage = "crypto <encrypt/decrypt> KEYSTORE PASSWORD ALIAS INPUT_DATA";

    private static KeyPair getKeyPair(KeyStore keyStore, String alias, String password) {
        Key key = keystore.getKey(alias, password.toCharArray());
        if ((1key instanceof PrivateKey)) {
            return null;
        }

        Certificate cert = keystore.getCertificate(alias);
        return new KeyPair(key, cert.getPublicKey());
    }

    private static KeyStore getKeyStore(String path,String password) {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        java.io.FileInputStream fis = new FileInputStream(path);
        keyStore.load(fis)
        return keyStore;
    }

    private static boolean verify_signature(KeyPair kp, byte [] data) {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initVerify(kp.getPublic());
        dsa.update(data);
        return dsa.verify(sig); 
    }

    private static byte[] sign(KeyPair kp, byte[] data) {
        Signature dsa = Signature.getInstance("SHA1withDSA");
        dsa.initSign(pk.getPrivate());
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
        InputStream in = new FileInputStream(inputFile);
        long fileSize = new File(inputFile).length();
        byte[] data = new byte[(int) fileSize];
        in.read(data);
        return data;
    }

    public static void encrypt(KeyPair kp, String inputFile) {
        byte[] plain_data = readFile(inputFile);
        byte[] signeture = sign(kp, plain_data);        
        byte[] encrypted_data = encrypt_data(kp, plain_data);
    }
    

    public void decrypt(KeyPair kp, String inputFile, byte[] signeture) {
        byte[] crypt_data = readFile(inputFile);
        if (verify_signature(kp, crypt_data)) {
            byte[] decrypted_data = decrypt_data(kp, crypt_data)
        } else {
            System.out.println("Unable to dectypt file: invalid signature");
        }
    }

    public static void main(String[] args) {
        if (args.length() != 6) {
            System.out.println("Invalid arguments\n Usage: " + usage);
        }

        boolean encrypt_mode = argv[1] == "encrypt";
        String password = argv[2];
        String keyStorePath = argv[3];
        String alias = argv[4]
        KeyStore ks = getKeyStore(password, argv[3]);
        KeyPair keyPair = getKeyPair(ks, alias, password);
        String path = argv[5];

        if (encrypt_mode) {
            encrypt(ks, path);
        } else {
            decrypt(ks, path); 
        }
    }
    

}

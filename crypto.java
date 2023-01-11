import java.security.*;

public class Crypto {
        private KeyStore keyStore;
        private String inputFilePath;
        private KeyPair keyPair;

        private static boolean verify_signature(InputStream in) {
            Signature dsa = Signature.getInstance("SHA1withDSA");
            dsa.initVerify(publicKey);
            /* Update and verify the data */
            dsa.update(data);
            boolean verifies = dsa.verify(sig); 
        }

        private static byte[] sign(InputStream in) {
            Signature dsa = Signature.getInstance("SHA1withDSA");
            /* Initializing the object with a private key */
            dsa.initSign(privateKey);
            dsa.update(data);
            return dsa.sign();
        }

        private static byte[] decrypt(InputStream in) {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
            String decryptedMessage = new String(plaintext);
        }

        private static byte[] encrypt(InputStream in) {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
            return cipher.doFinal(message.getBytes());
        }

        public static void main(String[] args) {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        // TODO: change those to into arguments
        char[] password = "Aa123456".toCharArray();
        String path = "alice.keystore";
        java.io.FileInputStream fis = new FileInputStream(path);

        Key key = keystore.getKey(alias, "password".toCharArray());
        if (key instanceof PrivateKey) {
            privateKey = key
            Ccert = keystore.   (alias);
            keyPair = new KeyPair(key, cert.getPublicKey());
        }

     
    }
}

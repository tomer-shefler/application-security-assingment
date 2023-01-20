package crypto;
import java.io.*;
import java.util.Properties;

public class Conf {
    boolean mode;
    String password;
    String alias;
    String peerAlias;
    String keyStorePath;
    String signature;
    Properties prop;


    public Conf() {

    }

    public void store(String path, String signature) throws FileNotFoundException, IOException {
        String alias = this.prop.getProperty("alias");
        String peerAlias = this.prop.getProperty("peerAlias");

        OutputStream output = new FileOutputStream(path);
        this.prop.setProperty("signature", signature);
        this.prop.setProperty("mode", "decrypt");
        this.prop.setProperty("keystore", peerAlias + ".keystore");
        this.prop.setProperty("alias", peerAlias);
        this.prop.setProperty("peerAlias", alias);
        this.prop.store(output, null);
    }

    public void load(String path) throws FileNotFoundException, IOException {
        InputStream input = new FileInputStream(path);
        this.prop = new Properties();
        this.prop.load(input);
        this.mode = this.prop.getProperty("mode").equals("encrypt");
        this.password = this.prop.getProperty("password");
        this.alias = prop.getProperty("alias");
        this.peerAlias = this.prop.getProperty("peerAlias");
        this.keyStorePath = this.prop.getProperty("keystore");

        String signature = this.prop.getProperty("signature");
        // Signature is required only for decrypt mode.
        if (signature != null) {
            this.signature = signature;
        }
    }
}

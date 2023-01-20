package crypto;
import java.io.*;
import java.util.Properties;

public class Conf {
    boolean mode;
    String password;
    String alias;
    String keyStorePath;
    String signature;
    Properties prop;

    public Conf() {

    }

    public void store(String path, String signature) throws FileNotFoundException, IOException {
        OutputStream output = new FileOutputStream(path);
        this.prop.setProperty("signature", signature);
        this.prop.setProperty("mode", "decrypt");
        this.prop.setProperty("keystore", "bob.keystore");
        this.prop.setProperty("alias", "bob");
        this.prop.store(output, null);
    }

    public void load(String path) throws FileNotFoundException, IOException {
        InputStream input = new FileInputStream(path);
        this.prop = new Properties();
        this.prop.load(input);
        this.mode = this.prop.getProperty("mode").equals("encrypt");
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

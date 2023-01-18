# Application security assingment
Create keysotre and keypair for Alice
```
keytool -genkey -alias alice -keyalg RSA -keystore alice.keystore -storetype JKS -storepass Aa1234
```

Create certificate for Alice
```
keytool -export -alias alice -keystore alice.keystore -rfc -file alice.cert
```

Create keysotre and keypair for Bob
```
keytool -genkey -alias bob -keyalg RSA -keystore bob.keystore -storetype JKS -storepass Aa1234
```

Create certificate for Bob
```
keytool -export -alias bob -keystore bob.keystore -rfc -file bob.cert
```

Import Bob's certificate to Alice's keystore
```
keytool -import -alias bob -file bob.cert -storetype JKS -keystore alice.keystore
```

Import Alice's certificate to Bob's keystore
```
keytool -import -alias alice -file alice.cert -storetype JKS -keystore bob.keystore
```

# Build
```
javac -d . Conf.java
javac -d . Crypto.java
```

# Run
### Encrypt
```
java crypto.Crypto conf plain_data
```

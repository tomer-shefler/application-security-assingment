# Application security assingment
Create keysotre and keypair for Alice
```
keytool -genkey -alias alice -keyalg RSA -keystore alice.keystore -storetype JKS -storepass Aa1234
```

Export certificate for Alice
```
keytool -export -alias alice -keystore alice.keystore -rfc -file alice.cert -storepass Aa1234
```

Create keysotre and keypair for Bob
```
keytool -genkey -alias bob -keyalg RSA -keystore bob.keystore -storetype JKS -storepass Aa1234
```

Export certificate for Bob
```
keytool -export -alias bob -keystore bob.keystore -rfc -file bob.cert -storepass Aa1234
```

Import Bob's certificate to Alice's keystore
```
keytool -import -alias bob -file bob.cert -storetype JKS -keystore alice.keystore -storepass Aa1234
```

Import Alice's certificate to Bob's keystore
```
keytool -import -alias alice -file alice.cert -storetype JKS -keystore bob.keystore -storepass Aa1234
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
### Decrypt
```
java crypto.Crypto conf.decryptor plain_data.cipher
```

package com.dor.jwt_security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class emisor {

    public static void main(String[] args) {
        // 1. leer llave privada del emisor
        // 2. leer llave publica del receptor
        // 3. firmar el mesaje 'Hola dani-or' 
        // 5. encriptar el string del paso 3
        // 6. El resultado del paso 5 se le pasa al receptor


        try {
            String privateNequiKeyString;
            privateNequiKeyString = new String(Files.readAllBytes(Paths.get(
                    "/home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate.pem")));

            System.out.println(privateNequiKeyString);
            RSAKey emisor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(privateNequiKeyString);

            System.out.println(emisor.getKeyType());
            System.out.println(emisor.isPrivate());

            String publicReceptorKeyString = new String(Files.readAllBytes(Paths
                    .get("/home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorpublic.pem")));
            System.out.println(publicReceptorKeyString);
            RSAKey receptor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(publicReceptorKeyString);

            System.out.println(receptor.getKeyType());
            System.out.println(receptor.isPrivate());

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(emisor.getKeyID()).build(),
                    new JWTClaimsSet.Builder().subject("Hola dani-or")
                            .issueTime(new Date()).issuer("https://c2id.com")
                            .build());

            // Sign the JWT
            signedJWT.sign(new RSASSASigner(emisor));

            // Flatt el firmado
            String jwsString = signedJWT.serialize();
            System.out.println(jwsString);

            // Create JWE object with signed JWT as payload String
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256,
                            EncryptionMethod.A256CBC_HS512).contentType("JWT")
                                    .build(),
                    new Payload(jwsString));

            // Encrypt with the recipient's public key
            jweObject.encrypt(new RSAEncrypter(receptor));

            // Serialize to JWE compact form
            String jweString = jweObject.serialize();
            System.out.println("encriptado " + jweString);

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}

package com.dor.jwt_security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

public class receptor {

    public static void main(String[] args) {
        // 1. leer  publico de redeban
        // 2. generar llaves nequis tomarlas de un archivo TODO
        // 3. firmar
        // 4. flat del firmado
        // 5. encriptar el flat en string
        // 6. construir flat del encriptado
        // 7 .Construir otra opción

        try {
            String emisorPublicKey;

            emisorPublicKey = new String(Files.readAllBytes(Paths.get(
                    "/home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorpublic.pem")));

            System.out.println(emisorPublicKey);
            RSAKey emisor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(emisorPublicKey);

            System.out.println(emisor.getKeyType());
            System.out.println(emisor.isPrivate());

            String receptorPrivateKey = new String(Files.readAllBytes(Paths
                    .get("/home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate.pem")));
            System.out.println( receptorPrivateKey);
            RSAKey receptor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(receptorPrivateKey);

            System.out.println(receptor.getKeyType());
            System.out.println(receptor.isPrivate());

            //Este mensaje fue el ultimo que generó en la linea 78 del emisor
            String m = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.sDYzMkWH7gpUvC5t9G46fpv6N3Wl_aV_L_9YPB_UHyry7Vzy_7-D3T0OrMEmCVgwZ83a2Z2DkMEH5NnJwAckiRl48q1s1AKz-asBxui4eDSSxTam1CV2Bs5giTl3b01VgM0gSYTRtPJCo7iiKDA0nW3N0SMTKaA26vDKFF1-F1R6CBLWbPK07wH0BESW_pJPzz_AP-NFiduQ1mNrvu4e_WB2c_L3lY568LYzw3oOfBJplApC4sxJDeAyvzZLaWZbmmZw6STvH78MFenDFO_QFzuDGiCP8AxlfZHTz5Hvz5spMuiF1JhB-ISbOVFEofSzPE0GEN8K4W87ku0WMIdvDA.LbUnRgdsa6Xoi8hRyRX2nw.hgwUawv-ZNO40EZTaQA1Xgydzn1EGr7YHmDW1--3d7MqhrbgGKtx6jL94Irtqc9j8GVDIyi5foyeB_8UKnZFMsdVySIePDpTdC4O-rbQB-aSIRpwQjMXyW3Dma5G_zhjY_fySI3n8nzHFtBoahRzJW5RswgXWxRzGR-hu-V4qGzQqQ1QOOVUrKAcdggD3fuM9SpJR6N4FXQZIF-CsECerFis26JPjcO--nm2S9nXjXeWmb1W-JqP1GbFQvFQzHGPrRhSYoHANazIoKlv-_InXjY-QydJXdSSCq77ROEiViTQAGYTYL1HFLc5geNslU5kxD_4I0AnV8r-DmgWwgSd-ffIP1JzsfnPdT_RsZ4sJ7B5TC2nzx0vyEQEjd2IMfAwWLCwS2V7Y_Bx9KxsI6w3MVoQul71aaEwhgDfZ-pR42nyPw0GJyvWOl1OW1HwBQrMR2gx3RVaK15kbKiHa11SbLp3dPQ5mYmR_dnyuhEx9hqJjdAvMnKf7ItrGD3YYAi4oSbisJUGsLHVX4p-krhmghbLIWXk7poIGxZ9zt-4fMOsM3LUrIIRcCK6Hj15zq57SUi68FP2CTTILn2WTbn84FpvaLmIxk-Etqp6n69gHmk.virZwDkS9eW3jRaZaa3_pQpUMMKkMR_P3JQhgvpY_ps";

            EncryptedJWT encryptedJWT;

            encryptedJWT = EncryptedJWT.parse(m);
            encryptedJWT.decrypt(new RSADecrypter(receptor));
            SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
            System.out.println(signedJWT.verify(new RSASSAVerifier(receptor)));
            //Este debe ser igual al que firmamos y encriptamos desde el emisor
            System.out.println(signedJWT.getJWTClaimsSet().getSubject());

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}

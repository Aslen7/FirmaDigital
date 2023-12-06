/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package firmadigital;

/**
 *
 * @author Lenovo
 */
import java.io.*;
import java.security.*;
import java.util.Base64;

public class FirmaDigital {
    public static void main(String[] args) {
        try {
            // Step 1: Create a document and generate digital signature
            String document = "This is a legal document.";
            KeyPair keyPair = generateKeyPair();
            String signature = signDocument(document, keyPair.getPrivate());

            // Step 2: Export public and private keys
            exportKeys(keyPair);

            // Step 3: Display the document, signature, and public key
            System.out.println("Original Document: " + document);
            System.out.println("Digital Signature: " + signature);
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

            // Step 4: Verify the document using the public key
            boolean isValid = verifyDocument(document, signature, keyPair.getPublic());
            if (isValid) {
                System.out.println("Document is valid.");
            } else {
                System.out.println("Document has been altered.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String signDocument(String document, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(document.getBytes("UTF-8"));
        byte[] signedBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signedBytes);
    }

    private static void exportKeys(KeyPair keyPair) throws IOException {
        try (ObjectOutputStream publicKeyStream = new ObjectOutputStream(new FileOutputStream("publicKey.key"));
             ObjectOutputStream privateKeyStream = new ObjectOutputStream(new FileOutputStream("privateKey.key"))) {

            publicKeyStream.writeObject(keyPair.getPublic());
            privateKeyStream.writeObject(keyPair.getPrivate());
        }
    }

    private static boolean verifyDocument(String document, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(document.getBytes("UTF-8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return verifier.verify(signatureBytes);
    }
}

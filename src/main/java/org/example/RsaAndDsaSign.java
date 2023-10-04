package org.example;

import java.security.*;
import java.util.Scanner;

public class RsaAndDsaSign
{
    private static byte[] sign(String plainText, PrivateKey privateKey, String algorithm) throws Exception {
        Signature privateSignature = Signature.getInstance(algorithm);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        byte[] signature = privateSignature.sign();
        return signature;
    }

    private static boolean verify(String plainText, byte[] signature, PublicKey publicKey, String algorithm) throws Exception {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        return publicSignature.verify(signature);
    }

    private static KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }
    private static void printSignature(byte[] signature) {
        for (int i = 0; i < signature.length; i++) {
            String hex = Integer.toHexString(signature[i]);
            System.out.print(hex.toUpperCase());
        }
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        final String[] algorithmSign = {"SHA256withRSA", "SHA256withDSA"};
        final String[] algorithmGenerateKey = {"RSA", "DSA"};

        Scanner in = new Scanner(System.in);
        System.out.print("Enter the string: ");
        String text = in.nextLine();

        SecureRandom sec = new SecureRandom();
        KeyPair RsaPair = generateKeyPair(algorithmGenerateKey[0]);
        KeyPair DsaPair = generateKeyPair(algorithmGenerateKey[1]);
        byte[] rsaSignature = sign(text, RsaPair.getPrivate(), algorithmSign[0]);
        boolean rsaVerify = verify(text, rsaSignature, RsaPair.getPublic(), algorithmSign[0]);
        byte[] dsaSignature = sign(text, DsaPair.getPrivate(), algorithmSign[1]);
        boolean dsaVerify = verify(text, dsaSignature, DsaPair.getPublic(), algorithmSign[1]);

        System.out.print("RSA Signature: ");
        printSignature(rsaSignature);
        System.out.printf("RSA verify: %b\n", rsaVerify);
        System.out.print("DSA Signature: ");
        printSignature(dsaSignature);
        System.out.printf("DSA Verify: %b\n", dsaVerify);
    }
}

package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * An example of an Owl exchange.
 * <p>
 * 
 * In this example, both the client and server are on the same computer (in the same JVM, in fact).
 * In reality, they would be in different locations,
 * and would be sending their generated payloads to each other.
 */
public class Owl_Example {

    public static void main(String args[]) throws CryptoException
    {
        /*
         * Initialization
         * 
         * Pick an appropriate elliptic curve to use throughout the exchange.
         * Note that both participants must use the same group.
         */
        Owl_Curve curve = Owl_Curves.NIST_P256;

        ECCurve ecCurve = curve.getCurve();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        ECPoint g = curve.getG(); 
        BigInteger h = curve.getH();
        BigInteger n = curve.getN();
        BigInteger q = curve.getQ();

        String serverPassword = "password";
        String clientPassword = "password";

        System.out.println("********* Initialization **********");
        System.out.println("Public parameters for the elliptic curve over prime field:");
    	System.out.println("Curve param a (" + a.bitLength() + " bits): "+ a.toString(16));
    	System.out.println("Curve param b (" + b.bitLength() + " bits): "+ b.toString(16));    	    	
    	System.out.println("Co-factor h (" + h.bitLength() + " bits): " + h.toString(16));
    	System.out.println("Base point G (" + g.getEncoded(true).length + " bytes): " + new BigInteger(g.getEncoded(true)).toString(16));
    	System.out.println("X coord of G (G not normalised) (" + g.getXCoord().toBigInteger().bitLength() + " bits): " + g.getXCoord().toBigInteger().toString(16));
    	System.out.println("y coord of G (G not normalised) (" + g.getYCoord().toBigInteger().bitLength() + " bits): " + g.getYCoord().toBigInteger().toString(16));
    	System.out.println("Order of the base point n (" + n.bitLength() + " bits): "+ n.toString(16));
    	System.out.println("Prime field q (" + q.bitLength() + " bits): "+ q.toString(16));
        System.out.println("");

        System.out.println("(Secret passwords used by Client and Server: " +
                "\"" + clientPassword + "\" and \"" + serverPassword + "\")\n");

        /*
         * Both participants must use the same hashing algorithm.
         */
        Digest digest = SHA256Digest.newInstance();
        SecureRandom random = new SecureRandom();

        Owl_Client client = new Owl_Client("client", clientPassword.toCharArray(), curve, digest, random);
        Owl_Server server = new Owl_Server("server", serverPassword.toCharArray(), curve, digest, random);

        /*
         * Initial User Registration
         * Client initiates registration using their username and password of choice and
         * sends a payload (over a secure channel) to the server which in turn safely
         * and securely stores (server storage is upto the user of this handshake protocol).
         */

        Owl_InitialRegistration clientUserRegistration = client.initiateUserRegistration();
        Owl_FinishRegistration serverUserRegistration = server.registerUseronServer(clientUserRegistration);

        System.out.println("************ User Registration **************");
        System.out.println("Client sends to Server: ");
        System.out.println("Username used to register = " + clientUserRegistration.getClientId());
        System.out.println("pi = " + clientUserRegistration.getPi().toString(16));
        System.out.println("g^{t}=" + new BigInteger(clientUserRegistration.getGt().getEncoded(true)).toString(16));
        System.out.println("");

        System.out.println("Server stores internally: ");
        System.out.println("Username used to register = " + serverUserRegistration.getClientId());
   	    System.out.println("KP{x3}: {V="+new BigInteger(serverUserRegistration.getKnowledgeProofForX3().getV().getEncoded(true)).toString(16)+"; r="+serverUserRegistration.getKnowledgeProofForX3().getr().toString(16)+"}");
        System.out.println("g^{x3}=" + new BigInteger(serverUserRegistration.getGx3().getEncoded(true)).toString(16));
        System.out.println("pi = " + serverUserRegistration.getPi().toString(16));
        System.out.println("g^{t}=" + new BigInteger(serverUserRegistration.getGt().getEncoded(true)).toString(16));
        System.out.println("");

        /*
         * First Pass
         * The client initiates the login authentication process by creating and sending a
         * payload to the server. 
         */

        Owl_AuthenticationInitiate clientLoginStart = client.authenticationInitiate();
        System.out.println("************ First Pass ************");
        System.out.println("Client sends to server: ");
        System.out.println("Username used to login: " + clientLoginStart.getClientId());
        System.out.println("g^{x1}=" + new BigInteger(clientLoginStart.getGx1().getEncoded(true)).toString(16));
        System.out.println("g^{x2}=" + new BigInteger(clientLoginStart.getGx2().getEncoded(true)).toString(16));
        System.out.println("KP{x1}: {V=" + new BigInteger(clientLoginStart.getKnowledgeProofForX1().getV().getEncoded(true)).toString(16) + "; r=" + clientLoginStart.getKnowledgeProofForX1().getr().toString(16) + "}");
        System.out.println("KP{x2}: {V=" + new BigInteger(clientLoginStart.getKnowledgeProofForX2().getV().getEncoded(true)).toString(16) + "; r=" + clientLoginStart.getKnowledgeProofForX2().getr().toString(16) + "}");
        System.out.println("");

        /*
         * Second Pass
         * The server validates the clients initial payload, and takes as input 
         * the internally stored client data from the server. It then creates and
         * sends its own payload back to the client.
         */

        Owl_AuthenticationServerResponse serverLoginResponse = server.authenticationServerResponse(clientLoginStart, serverUserRegistration);

        System.out.println("************ Second Pass **************");
        System.out.println("Server verifies the client's KP{x1}: OK\n");
        System.out.println("Server verifies the client's KP{x2}: OK\n");
        System.out.println("Server sends to Client: ");
        System.out.println("Server's unique ID: " + serverLoginResponse.getServerId());
        System.out.println("g^{x3}=" + new BigInteger(serverLoginResponse.getGx3().getEncoded(true)).toString(16));
        System.out.println("g^{x4}=" + new BigInteger(serverLoginResponse.getGx4().getEncoded(true)).toString(16));
        System.out.println("KP{x3}: {V=" + new BigInteger(serverLoginResponse.getKnowledgeProofForX3().getV().getEncoded(true)).toString(16) + "; r=" + serverLoginResponse.getKnowledgeProofForX3().getr().toString(16) + "}");
        System.out.println("KP{x4}: {V=" + new BigInteger(serverLoginResponse.getKnowledgeProofForX4().getV().getEncoded(true)).toString(16) + "; r=" + serverLoginResponse.getKnowledgeProofForX4().getr().toString(16) + "}");
    	System.out.println("Beta="+new BigInteger(serverLoginResponse.getBeta().getEncoded(true)).toString(16));
    	System.out.println("KP{Beta}: {V="+new BigInteger(serverLoginResponse.getKnowledgeProofForBeta().getV().getEncoded(true)).toString(16)+", r="+serverLoginResponse.getKnowledgeProofForBeta().getr().toString(16)+"}");
        System.out.println("");

        /*
         * Third Pass
         * The client recieves and valildates the server's response.
         * It then creates and sends the final payload of the handshake
         * (not including the explicit key confirmation).
         */

        Owl_AuthenticationFinish clientLoginEnd = client.authenticationFinish(serverLoginResponse);

        System.out.println("************ Third Pass ************");
        System.out.println("Client verifies the server's KP{x3}: OK\n");
        System.out.println("Client verifies the server's KP{x3}: OK\n");
        System.out.println("Client verifies the server's KP{Beta}: OK\n");   
        System.out.println("Client sends to Server: ");
        System.out.println("Username used to login" + clientLoginEnd.getClientId());
        System.out.println("Alpha="+new BigInteger(clientLoginEnd.getAlpha().getEncoded(true)).toString(16));
        System.out.println("KP{Alpha}: {V="+new BigInteger(clientLoginEnd.getKnowledgeProofForAlpha().getV().getEncoded(true)).toString(16)+", r="+clientLoginEnd.getKnowledgeProofForAlpha().getr().toString(16)+"}");

        /*
         * After the third pass, each participant computes the keying material.
         */

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        System.out.println("********* After Third Pass ***********");
        System.out.println("Client computes key material \t K=" + clientKeyingMaterial.toString(16));
        System.out.println("Server computes key material \t K=" + serverKeyingMaterial.toString(16));
        System.out.println();
        
        
        /*
         * You must derive a session key from the keying material applicable
         * to whatever encryption algorithm you want to use.
         */
        
        BigInteger clientKey = deriveSessionKey(clientKeyingMaterial);
        BigInteger serverKey = deriveSessionKey(serverKeyingMaterial);
        
        /*
         * At this point, you can stop and use the session keys if you want.
         * This is implicit key confirmation.
         * 
         * If you want to explicitly confirm that the key material matches,
         * you can continue on and perform key confirmation.
         */
        
        /*
         * Key Confirmation
         * 
         * Client and Server each generate a Key Confirmation payload, and send it to each other.
         */

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        System.out.println("************ Key Confirmation **************");
        System.out.println("Client sends to Server: ");
        System.out.println("MacTag=" + clientKCPayload.getMacTag().toString(16));
        System.out.println("");
        System.out.println("Server sends to Client: ");
        System.out.println("MacTag=" + serverKCPayload.getMacTag().toString(16));
        System.out.println("");

        /*
         * Each participant must then validate the received payload for Key Confirmation.
         */

        client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
        System.out.println("Client checks MacTag: OK\n");

        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);
        System.out.println("Server checks MacTag: OK\n");

        System.out.println();
        System.out.println("MacTags validated, therefore the keying material matches.");
    }

    private static BigInteger deriveSessionKey(BigInteger keyingMaterial)
    {
        /*
         * You should use a secure key derivation function (KDF) to derive the session key.
         * 
         * For the purposes of this example, I'm just going to use a hash of the keying material.
         */
        SavableDigest digest = SHA256Digest.newInstance();
        
        byte[] keyByteArray = keyingMaterial.toByteArray();
        
        byte[] output = new byte[digest.getDigestSize()];
        
        digest.update(keyByteArray, 0, keyByteArray.length);

        digest.doFinal(output, 0);

        return new BigInteger(output);
    }
}
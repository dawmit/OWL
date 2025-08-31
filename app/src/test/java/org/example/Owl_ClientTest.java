package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**import org.bouncycastle.crypto.agreement.ecjpake.Owl_Curve;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_Curves;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_Client;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_AuthenticationInitiate;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound2Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound3Payload;
*/
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ClientTest
    extends TestCase
{

    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String clientId = "clientId";
        char[] password = "password".toCharArray();

        new Owl_Client(clientId, password, curve, digest, random);

        // null clientId
        try
        {
            new Owl_Client(null, password, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null password
        try
        {
            new Owl_Client(clientId, null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // empty password
        try
        {
            new Owl_Client(clientId, "".toCharArray(), curve, digest, random);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // null curve
        try
        {
            new Owl_Client(clientId, password, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new Owl_Client(clientId, password, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new Owl_Client(clientId, password, curve, digest, null);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }
    }

    public void testSuccessfulExchange()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.autheticationFinish(serverLoginResponsePayload);
        server.authenticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        client.validateKeyConfirmation(serveKCPayload, clientKeyingMaterial);
        server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);

        assertEquals(serverKeyingMaterial, clientKeyingMaterial);

    }

    public void testIncorrectPassword()
        throws CryptoException
    {
        Owl_Client client = createClient();
        Owl_Server server = createServerWithWrongPassword();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        Owl_AuthenticationFinish clientLoginFinishPayload = client.autheticationFinish(serverLoginResponsePayload);
        server.autheticationServerEnd(clientLoginFinishPayload);

        BigInteger clientKeyingMaterial = client.calculateKeyingMaterial();
        BigInteger serverKeyingMaterial = server.calculateKeyingMaterial();

        Owl_KeyConfirmation clientKCPayload = client.initiateKeyConfirmation(clientKeyingMaterial);
        Owl_KeyConfirmation serverKCPayload = server.initiateKeyConfirmation(serverKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException
        try
        {
            client.validateKeyConfirmation(serverKCPayload, clientKeyingMaterial);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        try
        {
            server.validateKeyConfirmation(clientKCPayload, serverKeyingMaterial);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testStateValidation()
        throws CryptoException
    {

        Owl_Server server = createServer();
        Owl_Client client = createClient();

        // We're testing client here. Server is just used for help.

        // START USER LOGIN REGISTRATION CHECKS

        assertEquals(Owl_Client.REGISTRATION_NOT_CALLED, server.getRegistrationState());

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        //create client registration payload twice

        try
        {
            client.initiateUserRegistration();
            fail();
        }
        catch(IllegalStateException e)
        {
            // pass
        }

        // START LOGIN INITIALISATION CHECKS

        assertEquals(Owl_Client.STATE_INITIALIZED, client.getState());

        // call server login initialise function before client login initialisation.
        try 
        {
            server.authenticationServerResponse(null, null);
            fail();
        }
        catch(IllegalStateException e)
        {
            // pass 
        }

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();

        assertEquals(Owl_Client.STATE_LOGIN_INITIALISED, client.getState());

        //call client login intialisation twice.

        try 
        {
            client.authenticationInitiate();
            fail();
        }
        catch 
        {
            // pass
        }

        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        // START LOGIN FINISH CHECKS

        // create key before ending login authentication finish
        try
        {
            client.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        Owl_AuthenticationFinish clientLoginFinishPayload = client.auhenticationFinish(serverLoginResponsePayload);
        assertEquals(Owl_Client.STATE_LOGIN_FINISHED, client.getState());

        // create client login end twice
        try
        {
            client.authenticationFinish(serverLoginResponsePayload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        // START KEY CALCULATION CHECKS

        // begin key confirmation before calculating key

        try
        {
            client.initiateKeyConfirmation(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawServerKey = client.calculateKeyingMaterial();

        assertEquals(Owl_Client.STATE_KEY_CALCULATED, client.getState());

        // calculate key twice
        try
        {
            client.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawServerKey  = server.calculateKeyingMaterial();       

        // START KEY CONFIRMATION CHECKS

        // validate key confirmation before creating key confirmation payload.

        try 
        {
            client.validateKeyConfirmation(null, rawClientKey);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        Owl_KeyConfirmation clientKC  = client.initiateKeyConfirmation(rawClientKey);

        assertEquals(Owl_Client.STATE_KC_INITIALISED, client.getState());

        // initalise key confirmation twice
        try
        {
            client.initiateKeyConfirmation(rawClientKey);
            fail();
        }catch{
            // pass
        }

        Owl_KeyConfirmation serverKC = server.initiateKeyConfirmation(rawServerKey);

        client.validateKeyConfirmation(serverKC, rawClientKey);

        assertEquals(Owl_Client.STATE_KC_VALIDATED, client.getState());

        // try validate key confirmation twice

        try{
            client.validateKeyConfirmation(serverKC, rawClientKey);
            fail();
        }catch {
            //pass
        }

        server.validateKeyConfirmation(clientKC, rawServerKey);
    }

    public void testAuthenticationFinish()
        throws CryptoException
    {

        Owl_AuthenticationServerReponse serverLoginReponsePayload = runExchangeUntilPass3();
        //should succeed
        Owl_AuthenticationFinish clientLoginFinishPayload = createClient().authenticationFinish(serverLoginReponsePayload);

        // clientId is the same as serverId
        try 
        {
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                "client", 
                serverLoginResponsePayload.getGx3(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        // try gx3 is infinity
        Owl_Curve curve = Owl_Curves.NIST_P256;
        try 
        {
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                curve.getCurve().getInfinity(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        // try gx4 is infinity
        try 
        {
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                serverLoginResponsePayload.getGx3(),
                curve.getCurve().getInfinity(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        //validation of zero knowledge proof for X3 fails
        try 
        {
            Owl_AuthenticationServerResponse serverLoginResponsePayload2 = runExchangeUntilPass3();  
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                serverLoginResponsePayload.getGx3(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload2.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        //validation of zero knowledge proof for X4 fails
        try 
        {
            Owl_AuthenticationServerResponse serverLoginResponsePayload2 = runExchangeUntilPass3();
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                serverLoginResponsePayload.getGx3(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload2.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        // Beta is infinity
        try 
        {
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                serverLoginResponsePayload.getGx3(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                curve.getCurve().getInfinity(),
                serverLoginResponsePayload.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
        //validation of zero knowledge proof for Beta fails
        try 
        {
            Owl_AuthenticationServerResponse serverLoginResponsePayload2 = runExchangeUntilPass3();
            createClient().authenticationServerEnd(new Owl_AuthenticationServerResponse(
                serverLoginResponsePayload.getServerId(),
                serverLoginResponsePayload.getGx3(),
                serverLoginResponsePayload.getGx4(),
                serverLoginResponsePayload.getKnowledgeProofForX3(),
                serverLoginResponsePayload.getKnowledgeProofForX4(),
                serverLoginResponsePayload.getBeta(),
                serverLoginResponsePayload2.getKnowledgeProofForBeta()));
            fail();
        }
        catch 
        {
            // pass
        }
    }

    private Owl_Client createServer()
    {
        return new Owl_Client("server", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Client createClient()
    {
        return new Owl_Client("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Server createServertWithWrongPassword()
    {
        return new Owl_Server("server", "wrong".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_authenticationFinish runExchangeUntilPass3()
    {
        Owl_Client server = createServer();
        Owl_Client client = createClient();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        return server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);
    }
}
package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**import org.bouncycastle.crypto.agreement.ecjpake.Owl_Curve;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_Curves;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_Server;
import org.bouncycastle.crypto.agreement.ecjpake.Owl_AuthenticationInitiate;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound2Payload;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKERound3Payload;
*/
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Owl_ServerTest
    extends TestCase
{

    public void testConstruction()
        throws CryptoException
    {
        Owl_Curve curve = Owl_Curves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String serverId = "serverId";
        char[] password = "password".toCharArray();

        new Owl_Server(serverId, password, curve, digest, random);

        // null serverId
        try
        {
            new Owl_Server(null, password, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null password
        try
        {
            new Owl_Server(serverId, null, curve, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // empty password
        try
        {
            new Owl_Server(serverId, "".toCharArray(), curve, digest, random);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // null curve
        try
        {
            new Owl_Server(serverId, password, null, digest, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null digest
        try
        {
            new Owl_Server(serverId, password, curve, null, random);
            fail();
        }
        catch (NullPointerException e)
        {
            // pass
        }

        // null random
        try
        {
            new Owl_Server(serverId, password, curve, digest, null);
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
        Owl_Server server = createServer();
        Owl_Server client = createClientWithWrongPassword();

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

        // We're testing server here. client is just used for help.

        // START USER LOGIN REGISTRATION CHECKS

        assertEquals(Owl_Server.REGISTRATION_NOT_CALLED, server.getRegistrationState());

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        //create server registration payload twice

        try
        {
            server.registerUserOnServer(clientRegistrationPayload);
            fail();
        }
        catch(IllegalStateException e)
        {
            // pass
        }

        // START LOGIN INITIALISATION CHECKS

        assertEquals(Owl_Server.STATE_INITIALIZED, server.getState());

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();

        // call serve login end function before serve login response.
        try 
        {
            server.authenticationServerEnd(null);
        }
        catch(IllegalStateException e)
        {
            // pass 
        }

        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        assertEquals(Owl_Server.STATE_LOGIN_INITIALISED, server.getState());

        // create server login response twice
        try
        {
            Owl_AuthenticationServerResponse serverLoginResponsePayloadCopy = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        Owl_authenticationFinish clientLoginFinishPayload = client.authenticationFinish(serverLoginResponsePayload);

        // START LOGIN FINISH CHECKS

        // create key before ending login authentication
        try
        {
            server.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        server.authenticationServerEnd(clientLoginFinishPayload);

        assertEquals(Owl_Server.STATE_LOGIN_FINISHED, server.getState());

        // create server login end twice
        try
        {
            server.authenticationServerEnd(clientLoginFinishPayload);
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
            server.initiateKeyConfirmation(null);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawServerKey = server.calculateKeyingMaterial();

        assertEquals(Owl_Server.STATE_KEY_CALCULATED, server.getState());

        // calculate key twice
        try
        {
            server.calculateKeyingMaterial();
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        BigInteger rawClientKey  = client.calculateKeyingMaterial();       

        // START KEY CONFIRMATION CHECKS

        // validate key confirmation before creating key confirmation payload.

        try 
        {
            server.validateKeyConfirmation(null, rawServerKey);
            fail();
        }
        catch (IllegalStateException e)
        {
            // pass
        }

        Owl_KeyConfirmation serverKC  = server.initiateKeyConfirmation(rawServerKey);

        assertEquals(Owl_Server.STATE_KC_INITIALISED, server.getState());

        try
        {
            server.initiateKeyConfirmation(null);
            fail();
        }catch{
            // pass
        }

        Owl_KeyConfirmation clientKC = client.initiateKeyConfirmation(rawClientKey);

        server.validateKeyConfirmation(clientKC, rawServerKey);

        assertEquals(Owl_Server.STATE_KC_VALIDATED, server.getState());

        // try validate key confirmation twice

        try{
            server.validateKeyConfirmation(clientKC, rawServerKey);
            fail();
        }catch {
            //pass
        }

        client.validateKeyConfirmation(serverId, rawClientKey);


    }

    public void testAuthenticationServerResponse()
        throws CryptoException
    {

        // We're testing server here. client is just used for help.
        Owl_InitialRegistration clientRegistrationPayload = createClient().initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = createServer().registerUserOnServer(clientRegistrationPayload);
        Owl_AuthenticationInitiate clientAuthInit = createClient().authenticationInitiate();
        //should work
        Owl_AuthenticationServerResponse serverAuthinit = createServer().authenticationServerResponse(clientAuthInit, serverRegistrationPayload);

        //serverId and clientId are the same
        try 
        {
            createServer().authenticationServerResponse(new Owl_AuthenticationInitiate(
                "server",
                clientAuthInit.getGx1(), 
                clientAuthInit.getGx2(), 
                clientAuthInit.getKnowledgeProofForX1()
                clientAuthInit.getKnowledgeProofForX2()), serverRegistrationPayload);
            fail();
        }catch(CryptoException e)
        {
            // pass
        }

        // g^x1 = infinity
        Owl_Curve curve = Owl_Curves.NIST_P256;
        try
        {
            createServer().authenticationServerResponse(new Owl_AuthenticationInitiate(
                clientAuthInit.getClientId(), 
                curve.getCurve().getInfinity(),                
                clientAuthInit.getGx2(), 
                clientAuthInit.getKnowledgeProofForX1()
                clientAuthInit.getKnowledgeProofForX2()),serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // g^x2 = infinity
        try
        {
            createServer().authenticationServerResponse(new Owl_AuthenticationInitiate(
                clientAuthInit.getClientId(),
                clientAuthInit.getGx1(), 
                curve.getCurve().getInfinity(),                
                clientAuthInit.getKnowledgeProofForX1()
                clientAuthInit.getKnowledgeProofForX2()), serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x1 fails
        try
        {
            Owl_AuthenticationInitiate clientAuthInit2 = createClient().authenticationInitiate();
            createServer().authenticationServerResponse(new Owl_AuthenticationInitiate(
                clientAuthInit.getClientId(),
                clientAuthInit.getGx1(), 
                clientAuthInit.getGx2(),                
                clientAuthInit2.getKnowledgeProofForX1()
                clientAuthInit.getKnowledgeProofForX2()), serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // zero knowledge proof for x2 fails
        try
        {
            Owl_AuthenticationInitiate clientAuthInit2 = createClient().authenticationInitiate();
            createServer().authenticationServerResponse(new Owl_AuthenticationInitiate(
                clientAuthInit.getClientId(),
                clientAuthInit.getGx1(), 
                clientAuthInit.getGx2(),                
                clientAuthInit.getKnowledgeProofForX1()
                clientAuthInit2.getKnowledgeProofForX2()), serverRegistrationPayload);
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }

        // clientId from server is on the same as the clientId from payload
        try 
        {
            createServer().authenticationServerResponse(clientAuthInit, new Owl_FinishRegistration(
                "server", 
                serverRegistrationPayload.getKnowledgeProofForX3(), 
                serverRegistrationPayload.getGx3(),
                serverRegistrationPayload.getPi(),
                serverRegistrationPayload.getGt()));
            fail();
        }
        catch (CryptoException e)
        {
            // pass
        }
    }

    public void testAuthenticationServerEnd()
        throws CryptoException
    {

        Owl_AuthenticationFinish clientLoginFinishPayload = runExchangeUntilPass3();
        //should succeed
        server.authenticationServerEnd(clientLoginFinishPayload);

        // clientId is the same as serverId
        try 
        {
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                "server", 
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch 
        {
            // pass
        }
        //clientId from previous function {@link #authenticationServerResponse} is not equal to the clientId from payload.
        try 
        {
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                "client2",
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch 
        {
            // pass
        }
        //validation of alpha fails by incorrect alpha
        try 
        {
            Owl_AuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3();
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload2.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch 
        {
            // pass
        }
        //validation of alpha fails by incorrect knowledge proof
        try 
        {
            Owl_AuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3();
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload2.getKnowledgeProofForAlpha(),
                clientLoginFinishPayload.getR()));
            fail();
        }
        catch 
        {
            // pass
        }
        //incorrect r value
        try 
        {
            Owl_AuthenticationFinish clientLoginFinishPayload2 = runExchangeUntilPass3();
            createServer().authenticationServerEnd(new Owl_AuthenticationFinish(
                clientLoginFinishPayload.getClientId(),
                clientLoginFinishPayload.getAlpha(),
                clientLoginFinishPayload.getKnowledgeProofForAlpha,
                clientLoginFinishPayload2.getR()));
            fail();
        }
        catch 
        {
            // pass
        }
    }

    private Owl_Server createServer()
    {
        return new Owl_Server("server", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Server createClient()
    {
        return new Owl_Client("client", "password".toCharArray(), Owl_Curves.NIST_P256);
    }

    private Owl_Server createClientWithWrongPassword()
    {
        return new Owl_Client("client", "wrong".toCharArray(), Owl_Curves.NIST_P256);
    }
    private Owl_authenticationFinish runExchangeUntilPass3()
    {
        Owl_Server server = createServer();
        Owl_Client client = createClient();

        Owl_InitialRegistration clientRegistrationPayload = client.initiateUserRegistration();
        Owl_FinishRegistration serverRegistrationPayload = server.registerUserOnServer(clientRegistrationPayload);

        Owl_AuthenticationInitiate clientLoginInitialPayload = client.authenticationInitiate();
        Owl_AuthenticationServerResponse serverLoginResponsePayload = server.authenticationServerResponse(clientLoginInitialPayload, serverRegistrationPayload);

        return client.autheticationFinish(serverLoginResponsePayload);
    }
}
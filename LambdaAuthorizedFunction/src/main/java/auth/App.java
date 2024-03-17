package auth;

import java.util.*;
import com.amazonaws.services.cognitoidp.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import entity.AuthRequest;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String REGION = System.getenv("REGION");
    private static final String USER_POOL_ID = System.getenv("USER_POOL_ID");
    private static final String APP_CLIENT_ID = System.getenv("APP_CLIENT_ID");

    private final AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder
            .standard()
            .withRegion(REGION)
            .build();

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent().withHeaders(headers);

        try {
            ObjectMapper mapper = new ObjectMapper();
            AuthRequest obj = mapper.readValue(input.getBody(), AuthRequest.class);

            String cpf = obj.getCpf();
            String password = obj.getPassword();

            System.out.println("start authentication with CPF:" + cpf);
            if (!isValidCPF(cpf)) {
                return response
                        .withStatusCode(400) // Bad Request
                        .withBody("Invalid CPF");
            }

            String accessToken = authenticateUser(cpf, password);

            return response
                    .withStatusCode(200)
                    .withBody("{\"accessToken\": \"" + accessToken + "\"}");

        } catch (Exception e) {
            return response
                    .withStatusCode(401)
                    .withBody("Invalid Credentials: " + e.getMessage());
        }
    }

    private String authenticateUser(String cpf, String password) {
        try {
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", cpf);
            authParameters.put("PASSWORD", password);

            System.out.println("start change password success");
            AdminSetUserPasswordRequest request = new AdminSetUserPasswordRequest()
                    .withUserPoolId(USER_POOL_ID)
                    .withUsername(cpf)
                    .withPassword(password)
                    .withPermanent(true);

            cognitoClient.adminSetUserPassword(request);
            System.out.println("finish change password success");

            System.out.println("start auth request");
            AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withClientId(APP_CLIENT_ID)
                    .withUserPoolId(USER_POOL_ID)
                    .withAuthParameters(authParameters);

            AdminInitiateAuthResult authResult = cognitoClient.adminInitiateAuth(authRequest);

            System.out.println("Authentication successfu 1: " + authResult.getAuthenticationResult().getIdToken());
            System.out.println("Authentication successfu 2: " + authResult.getAuthenticationResult().getAccessToken());
            System.out.println("Authentication successfu 3: " + authResult.getChallengeName());

            return authResult.getAuthenticationResult().getAccessToken();

        } catch (Exception e) {
            throw new RuntimeException("Authentication failed:"+ e.getMessage());
        }
    }

    private static void createUserWithCPF(AWSCognitoIdentityProvider cognitoIdentityProvider, String cpf, String password) {
        // Set up attributes for user creation
        List<AttributeType> userAttributes = new ArrayList<>();
        userAttributes.add(new AttributeType().withName("custom:cpf").withValue(cpf));

        // Create user request
        AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest()
                .withUserPoolId(USER_POOL_ID)
                .withUsername(cpf)
                .withTemporaryPassword(password)
                .withUserAttributes(userAttributes);

        // Create user
        AdminCreateUserResult createUserResult = cognitoIdentityProvider.adminCreateUser(createUserRequest);
        System.out.println("User created: " + createUserResult.getUser().getUsername());

        AdminSetUserPasswordRequest request = new AdminSetUserPasswordRequest()
                .withUserPoolId(USER_POOL_ID)
                .withUsername(cpf)
                .withPassword(password)
                .withPermanent(true);

        cognitoIdentityProvider.adminSetUserPassword(request);
        System.out.println("change password success");

    }

    private boolean isValidCPF(String cpf) {
        if (cpf == null || cpf.length() != 11 || !cpf.matches("[0-9]+")) {
            return false;
        }
        return true;
    }
}

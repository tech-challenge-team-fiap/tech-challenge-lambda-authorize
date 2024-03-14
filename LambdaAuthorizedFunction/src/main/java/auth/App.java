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

    private static final String REGION = "us-east-2";
    private static final String USER_POOL_ID = "us-east-2_uipxoOQn3";
    private static final String APP_CLIENT_ID = "41alb7cnri4rd5oou56rk37o8e";

    private final AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder
            .standard()
            .withRegion(REGION)
            .build();

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        System.out.println("Start processing ");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);

        System.out.println("finish processing ");

        try {
            //Get Data of Body Request
            ObjectMapper mapper = new ObjectMapper();

            System.out.println("authrequest processing ");
            AuthRequest obj = mapper.readValue(input.getBody(), AuthRequest.class);


            String cpf = obj.getCpf();
            String password = obj.getPassword();

            System.out.println("CPF:" + cpf + " -- PASSWORD: " + password);

            // Create a user in Cognito with CPF and password
            System.out.println("call creating user");
            createUserWithCPF(cognitoClient, cpf, password);

            System.out.println("valid cpf user");
            if (!isValidCPF(cpf)) {
                return response
                        .withStatusCode(400) // Bad Request
                        .withBody("Invalid CPF");
            }

            // Authenticate the user
            System.out.println("start call authenticateUser");
            String accessToken = authenticateUser(cpf, password);

            return response
                    .withStatusCode(200)
                    .withBody("{\"accessToken\": \"" + accessToken + "\"}");

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return response
                    .withStatusCode(401)
                    .withBody("Invalid Credentials");
        }
    }

    private String authenticateUser(String cpf, String password) {
        try {
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", cpf);
            authParameters.put("PASSWORD", password);

            AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withClientId(APP_CLIENT_ID)
                    .withUserPoolId(USER_POOL_ID)
                    .withAuthParameters(authParameters);

            AdminInitiateAuthResult authResult = cognitoClient.adminInitiateAuth(authRequest);
            System.out.println("Authentication successful");

            return authResult.getAuthenticationResult().getAccessToken();

        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
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

package auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;


import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.joda.time.DateTime;

/**
 * Handler for requests to Lambda function.
 */
public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final String REGION = "";
    private static final String USER_POOL_ID = "";
    private static final String APP_CLIENT_ID = "";

    private final AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
            .withRegion(REGION).build();

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);

        try {
            String cpf = input.getBody();
            String password = input.getBody();

            if (!isValidCPF(cpf)) {
                return response
                        .withStatusCode(400) // Bad Request
                        .withBody("Invalid CPF");
            }

            // Authenticate the user
            String accessToken = authenticateUser(cpf, password);

            return response
                    .withStatusCode(200)
                    .withBody("{\"accessToken\": \"" + accessToken + "\"}");

        } catch (Exception e) {
            return response
                    .withStatusCode(401)
                    .withBody("Invalid Credentials");
        }
    }

    private String authenticateUser(String cpf, String password) {
        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withUserPoolId(USER_POOL_ID)
                .withClientId(APP_CLIENT_ID)
                .withAuthParameters(Map.of(
                        "CPF", cpf,
                        "PASSWORD", password
                ));

        try {
            AdminInitiateAuthResult authResult = cognitoClient.adminInitiateAuth(authRequest);
            return authResult.getAuthenticationResult().getAccessToken();

        } catch (Exception e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }

    private boolean isValidCPF(String cpf) {
        if (cpf == null || cpf.length() != 11 || !cpf.matches("[0-9]+")) {
            return false;
        }

        int[] cpfArray = cpf.chars().map(Character::getNumericValue).toArray();

        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += cpfArray[i] * (10 - i);
        }
        int firstCheckDigit = 11 - (sum % 11);
        firstCheckDigit = (firstCheckDigit == 10) ? 0 : firstCheckDigit;

        sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += cpfArray[i] * (11 - i);
        }
        int secondCheckDigit = 11 - (sum % 11);
        secondCheckDigit = (secondCheckDigit == 10) ? 0 : secondCheckDigit;

        return cpfArray[9] == firstCheckDigit && cpfArray[10] == secondCheckDigit;
    }

    private String getPageContents(String address) throws IOException{
        URL url = new URL(address);
        try(BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()))) {
            return br.lines().collect(Collectors.joining(System.lineSeparator()));
        }
    }
}

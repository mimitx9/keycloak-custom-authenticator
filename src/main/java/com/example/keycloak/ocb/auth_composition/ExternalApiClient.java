package com.example.keycloak.ocb.auth_composition;

import com.example.keycloak.ocb.authenticate.client.OcbClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class ExternalApiClient {
    private static final Logger logger = Logger.getLogger(OcbClient.class);
    private static final String SUCCESS_CODE = "00";
    private static final String CONTENT_TYPE = "application/json";
    private static final String DEFAULT_ERROR_MESSAGE = "Lỗi không xác định";

    private final String apiUrl;
    private final String authHeader;
    private final int timeoutSeconds;
    private final ObjectMapper mapper = new ObjectMapper();

    public ExternalApiClient(String apiUrl, String username, String password, int timeoutSeconds) {
        this.apiUrl = apiUrl;
        this.authHeader = "Basic " + Base64.getEncoder().encodeToString(
                (username + ":" + password).getBytes(StandardCharsets.UTF_8)
        );
        this.timeoutSeconds = timeoutSeconds;
    }

    public ApiResponse verifyUser(String username, String password) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setConnectTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setSocketTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .build();

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            logger.infof("Calling external API at URL: %s with timeout: %d seconds", apiUrl, timeoutSeconds);
            HttpPost httpPost = new HttpPost(apiUrl);

            httpPost.setHeader("Authorization", authHeader);
            httpPost.setHeader("Content-Type", CONTENT_TYPE);
            httpPost.setHeader("Accept", CONTENT_TYPE);

            ObjectNode requestBody = mapper.createObjectNode();
            requestBody.put("userName", username);
            requestBody.put("password", password);

            String jsonBody = mapper.writeValueAsString(requestBody);
            logger.infof("Calling API for user: %s", username); // Không log password

            StringEntity stringEntity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
            stringEntity.setContentType(CONTENT_TYPE);
            httpPost.setEntity(stringEntity);

            logger.info("Executing HTTP request");
            try (CloseableHttpResponse response = client.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                logger.infof("Response status code: %d", statusCode);

                if (statusCode == 200) {
                    return handleSuccessHttpStatus(response);
                } else {
                    return handleHttpErrorStatus(statusCode, response);
                }
            }
        } catch (SocketTimeoutException e) {
            logger.error("Request timeout after " + timeoutSeconds + " seconds", e);
            return ApiResponse.error("TIMEOUT", DEFAULT_ERROR_MESSAGE);
        } catch (IOException e) {
            logger.error("IO error calling external API", e);
            return ApiResponse.error("CONNECTION_ERROR", DEFAULT_ERROR_MESSAGE);
        } catch (Exception e) {
            logger.error("Unexpected error calling external API", e);
            return ApiResponse.error("UNEXPECTED_ERROR", DEFAULT_ERROR_MESSAGE);
        }
    }

    private ApiResponse handleSuccessHttpStatus(CloseableHttpResponse response) {
        try {
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                logger.warn("API response entity is null");
                return ApiResponse.error("NULL_RESPONSE", DEFAULT_ERROR_MESSAGE);
            }

            String responseString = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            logger.infof("API Response: %s", responseString);

            if (responseString.isEmpty()) {
                logger.warn("Response string is empty");
                return ApiResponse.error("EMPTY_RESPONSE", DEFAULT_ERROR_MESSAGE);
            }

            return parseApiResponse(responseString);

        } catch (IOException e) {
            logger.error("Error reading response entity", e);
            return ApiResponse.error("RESPONSE_READ_ERROR", DEFAULT_ERROR_MESSAGE);
        }
    }

    private ApiResponse parseApiResponse(String responseString) {
        try {
            JsonNode jsonResponse = mapper.readTree(responseString);

            String code = getTextSafely(jsonResponse, "code");
            String message = getTextSafely(jsonResponse, "message");

            logger.infof("API Response - Code: %s, Message: %s", code, message);

            // Chỉ khi code = "00" thì mới là success
            if (SUCCESS_CODE.equals(code)) {
                return parseSuccessResponse(jsonResponse);
            } else {
                // Tất cả các code khác đều là lỗi
                logger.warnf("API returned error code: %s, message: %s", code, message);
                String errorMessage = (message != null && !message.isEmpty()) ? message : DEFAULT_ERROR_MESSAGE;
                return ApiResponse.error(code, errorMessage);
            }

        } catch (Exception e) {
            logger.error("Error parsing JSON response", e);
            return ApiResponse.error("PARSE_ERROR", DEFAULT_ERROR_MESSAGE);
        }
    }

    private ApiResponse parseSuccessResponse(JsonNode jsonResponse) {
        if (!jsonResponse.has("data")) {
            logger.warn("Success response but no data field");
            return ApiResponse.error("NO_DATA", DEFAULT_ERROR_MESSAGE);
        }

        JsonNode data = jsonResponse.get("data");
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("customerNumber", getTextSafely(data, "customerNumber"));
        userInfo.put("username", getTextSafely(data, "userName"));
        userInfo.put("fullName", getTextSafely(data, "fullName"));
        userInfo.put("email", getTextSafely(data, "email"));
        userInfo.put("mobile", getTextSafely(data, "mobile"));

        logger.info("Successfully parsed user info from API response");
        return ApiResponse.success(userInfo);
    }

    private ApiResponse handleHttpErrorStatus(int statusCode, CloseableHttpResponse response) {
        logger.warnf("HTTP error status: %d", statusCode);

        String apiMessage = "";
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                String responseString = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                logger.infof("Error response body: %s", responseString);

                try {
                    JsonNode errorJson = mapper.readTree(responseString);
                    String message = getTextSafely(errorJson, "message");
                    if (!message.isEmpty()) {
                        apiMessage = message;
                    }
                } catch (Exception e) {
                    logger.warn("Could not parse error response JSON", e);
                }
            }
        } catch (Exception e) {
            logger.warn("Could not read error response body", e);
        }

        String errorMessage = (apiMessage != null && !apiMessage.isEmpty()) ? apiMessage : DEFAULT_ERROR_MESSAGE;
        return ApiResponse.error("HTTP_" + statusCode, errorMessage);
    }

    private String getTextSafely(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return (field != null) ? field.asText("") : "";
    }
}
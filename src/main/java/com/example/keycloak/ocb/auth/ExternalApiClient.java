package com.example.keycloak.ocb.auth;

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
    private static final Logger logger = Logger.getLogger(ExternalApiClient.class);
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
        // Cấu hình timeout
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

            // Set headers
            httpPost.setHeader("Authorization", authHeader);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Accept", "application/json");

            // Tạo request body theo format mới
            ObjectNode requestBody = mapper.createObjectNode();
            requestBody.put("userName", username);  // Đổi từ "username" thành "userName"
            requestBody.put("password", password);

            String jsonBody = mapper.writeValueAsString(requestBody);
            logger.infof("Request body: %s", jsonBody);

            StringEntity stringEntity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
            stringEntity.setContentType("application/json");
            httpPost.setEntity(stringEntity);

            // Execute request
            logger.info("Executing HTTP request");
            try (CloseableHttpResponse response = client.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                logger.infof("Response status code: %d", statusCode);

                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    String responseString = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                    logger.infof("API Response: %s", responseString);

                    if (responseString.isEmpty()) {
                        logger.warn("Response string is empty");
                        return ApiResponse.error("EMPTY_RESPONSE", "Empty response from API");
                    }

                    try {
                        JsonNode jsonResponse = mapper.readTree(responseString);

                        // Lấy code và message
                        String code = getTextSafely(jsonResponse, "code");
                        String message = getTextSafely(jsonResponse, "message");

                        logger.infof("API Response - Code: %s, Message: %s", code, message);

                        if ("00".equals(code)) {
                            // Success case
                            if (!jsonResponse.has("data")) {
                                logger.warn("Success response but no data field");
                                return ApiResponse.error(code, "No user data in response");
                            }

                            JsonNode data = jsonResponse.get("data");
                            Map<String, String> userInfo = new HashMap<>();
                            userInfo.put("customerNumber", getTextSafely(data, "customerNumber"));
                            userInfo.put("username", getTextSafely(data, "userName"));  // Sử dụng userName
                            userInfo.put("fullName", getTextSafely(data, "fullName"));
                            userInfo.put("email", getTextSafely(data, "email"));
                            userInfo.put("mobile", getTextSafely(data, "mobile"));

                            logger.info("Successfully parsed user info from API response");
                            return ApiResponse.success(userInfo);
                        } else {
                            // Error cases
                            logger.warnf("API returned error code: %s, message: %s", code, message);
                            return ApiResponse.error(code, message);
                        }
                    } catch (Exception e) {
                        logger.error("Error parsing JSON response", e);
                        return ApiResponse.error("PARSE_ERROR", "Failed to parse API response");
                    }
                } else {
                    logger.warn("API response entity is null");
                    return ApiResponse.error("NULL_RESPONSE", "Null response from API");
                }
            }
        } catch (SocketTimeoutException e) {
            logger.error("Request timeout after " + timeoutSeconds + " seconds", e);
            return ApiResponse.timeout();
        } catch (IOException e) {
            logger.error("IO error calling external API", e);
            return ApiResponse.connectionError();
        } catch (Exception e) {
            logger.error("Unexpected error calling external API", e);
            return ApiResponse.error("UNEXPECTED_ERROR", "Unexpected error occurred");
        }
    }

    private String getTextSafely(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return (field != null) ? field.asText("") : "";
    }
}
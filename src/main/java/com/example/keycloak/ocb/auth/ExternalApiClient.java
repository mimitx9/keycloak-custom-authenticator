package com.example.keycloak.ocb.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ExternalApiClient {
    private static final Logger logger = Logger.getLogger(ExternalApiClient.class);
    private final String apiUrl;
    private final String authHeader;
    private final ObjectMapper mapper = new ObjectMapper();

    public ExternalApiClient(String apiUrl, String username, String password) {
        this.apiUrl = apiUrl;
        this.authHeader = "Basic " + Base64.getEncoder().encodeToString(
                (username + ":" + password).getBytes(StandardCharsets.UTF_8)
        );
    }

    public Map<String, String> verifyUser(String username, String password) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            logger.infof("Calling external API at URL: %s", apiUrl);
            HttpPost httpPost = new HttpPost(apiUrl);

            // Set headers
            httpPost.setHeader("Authorization", authHeader);
            httpPost.setHeader("Content-Type", "application/json");
            logger.info("Headers set");

            // Thay đổi cách tạo request body - sử dụng writeValueAsString thay vì toString()
            ObjectNode requestBody = mapper.createObjectNode();
            requestBody.put("username", username);
            requestBody.put("password", password);

            // Chuyển đổi ObjectNode thành chuỗi JSON đúng định dạng
            String jsonBody = mapper.writeValueAsString(requestBody);
            logger.infof("Request body: %s", jsonBody);

            // Tạo StringEntity từ chuỗi JSON
            StringEntity stringEntity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
            stringEntity.setContentType("application/json");
            httpPost.setEntity(stringEntity);

            // In ra thông tin request trước khi gửi
            logger.infof("Request method: %s", httpPost.getMethod());
            logger.infof("Request URI: %s", httpPost.getURI());
            Arrays.stream(httpPost.getAllHeaders()).forEach(header ->
                    logger.infof("Request header: %s: %s", header.getName(), header.getValue())
            );

            // Execute request
            logger.info("Executing HTTP request");
            try (CloseableHttpResponse response = client.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                logger.infof("Response status code: %d", statusCode);

                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    String responseString = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                    logger.infof("API Response (length: %d): %s", responseString.length(), responseString);

                    if (responseString.isEmpty()) {
                        logger.warn("Response string is empty");
                        return null;
                    }

                    try {
                        JsonNode jsonResponse = mapper.readTree(responseString);

                        // Log toàn bộ cấu trúc JSON để debug
                        logger.infof("JSON response structure: %s", jsonResponse.toString());

                        if (!jsonResponse.has("code")) {
                            logger.warn("JSON response does not contain 'code' field");
                            return null;
                        }

                        String code = jsonResponse.get("code").asText();
                        logger.infof("Response code: %s", code);

                        if ("00".equals(code)) {
                            if (!jsonResponse.has("data")) {
                                logger.warn("JSON response does not contain 'data' field");
                                return null;
                            }

                            JsonNode data = jsonResponse.get("data");
                            Map<String, String> userInfo = new HashMap<>();
                            userInfo.put("customerNumber", getTextSafely(data, "customerNumber"));
                            userInfo.put("username", getTextSafely(data, "username"));
                            userInfo.put("fullName", getTextSafely(data, "fullName"));
                            userInfo.put("email", getTextSafely(data, "email"));
                            userInfo.put("mobile", getTextSafely(data, "mobile"));
                            logger.info("Successfully parsed user info from API response");
                            return userInfo;
                        } else {
                            logger.warnf("API returned non-success code: %s", code);
                            return null;
                        }
                    } catch (Exception e) {
                        logger.error("Error parsing JSON response", e);
                        logger.infof("Raw response for troubleshooting: %s", responseString);
                        return null;
                    }
                } else {
                    logger.warn("API response entity is null");
                    return null;
                }
            } catch (Exception e) {
                logger.error("Error processing API response", e);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error calling external API", e);
            return null;
        }
    }

    private String getTextSafely(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return (field != null) ? field.asText("") : "";
    }
}
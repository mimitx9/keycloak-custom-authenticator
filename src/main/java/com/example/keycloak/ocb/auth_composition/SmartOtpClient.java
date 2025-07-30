package com.example.keycloak.ocb.auth_composition;

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
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class SmartOtpClient {
    private static final Logger logger = Logger.getLogger(SmartOtpClient.class);

    private static final Set<String> SUCCESS_CODES = Set.of("00", "0", "0000", "SUCCESS");

    private final String baseUrl;
    private final String apiKey;
    private final int timeoutSeconds;

    private final String otpPrefix;
    private final ObjectMapper mapper = new ObjectMapper();

    public SmartOtpClient(String baseUrl, String apiKey, int timeoutSeconds, String otpPrefix) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.timeoutSeconds = timeoutSeconds;
        this.otpPrefix = otpPrefix;
    }

    public OtpResponse createTransaction(String userId, String transactionId, String transactionData,
                                         int transactionTypeId, String challenge, String callbackUrl,
                                         int online, int push, String notificationTitle,
                                         String notificationBody, int esignerTypeId, int channelId, int maxOtpPerDay) {

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setConnectTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setSocketTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .build();

        String url = baseUrl + "/transaction";

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            logger.infof("Creating OTP transaction at URL: %s for user: %s", url, userId);
            HttpPost httpPost = new HttpPost(url);

            httpPost.setHeader("apikey", apiKey);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("x-request-id", java.util.UUID.randomUUID().toString());

            ObjectNode requestBody = mapper.createObjectNode();
            requestBody.put("userId", userId);
            requestBody.put("transactionData", transactionData);
            requestBody.put("transactionId", transactionId);
            requestBody.put("transactionTypeId", transactionTypeId);
            requestBody.put("challenge", challenge);
            requestBody.put("callbackUrl", callbackUrl);
            requestBody.put("online", online);
            requestBody.put("push", push);

            ObjectNode notificationInfo = mapper.createObjectNode();
            notificationInfo.put("title", notificationTitle);
            notificationInfo.put("body", notificationBody);
            requestBody.set("notificationInfo", notificationInfo);

            requestBody.put("esignerTypeId", esignerTypeId);
            requestBody.put("channelId", channelId);

            String jsonBody = mapper.writeValueAsString(requestBody);
            logger.infof("OTP Transaction request body: %s", jsonBody);

            StringEntity stringEntity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
            stringEntity.setContentType("application/json");
            httpPost.setEntity(stringEntity);

            try (CloseableHttpResponse response = client.execute(httpPost)) {
                return handleOtpResponse(response);
            }

        } catch (SocketTimeoutException e) {
            logger.error("Request timeout after " + timeoutSeconds + " seconds", e);
            return OtpResponse.timeout();
        } catch (IOException e) {
            logger.error("IO error calling OTP API", e);
            return OtpResponse.connectionError();
        } catch (Exception e) {
            logger.error("Unexpected error calling OTP API", e);
            return OtpResponse.error("UNEXPECTED_ERROR", "Unexpected error occurred");
        }
    }

    public OtpResponse verifyOtp(String userId, String otpNumber, String transactionId) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setConnectTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .setSocketTimeout((int) TimeUnit.SECONDS.toMillis(timeoutSeconds))
                .build();

        String url = baseUrl + "/advance/verify";
        otpNumber = otpPrefix + otpNumber;
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            logger.infof("Verifying OTP at URL: %s for user: %s", url, userId);
            HttpPost httpPost = new HttpPost(url);

            httpPost.setHeader("apikey", apiKey);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("x-request-id", java.util.UUID.randomUUID().toString());

            ObjectNode requestBody = mapper.createObjectNode();
            requestBody.put("userId", userId);
            requestBody.put("otpNumber", otpNumber);
            requestBody.put("transactionId", transactionId);

            String jsonBody = mapper.writeValueAsString(requestBody);
            logger.infof("OTP Verify request body: %s", jsonBody);

            StringEntity stringEntity = new StringEntity(jsonBody, StandardCharsets.UTF_8);
            stringEntity.setContentType("application/json");
            httpPost.setEntity(stringEntity);

            try (CloseableHttpResponse response = client.execute(httpPost)) {
                return handleOtpResponse(response);
            }

        } catch (SocketTimeoutException e) {
            logger.error("Request timeout after " + timeoutSeconds + " seconds", e);
            return OtpResponse.timeout();
        } catch (IOException e) {
            logger.error("IO error calling OTP verify API", e);
            return OtpResponse.connectionError();
        } catch (Exception e) {
            logger.error("Unexpected error calling OTP verify API", e);
            return OtpResponse.error("UNEXPECTED_ERROR", "Unexpected error occurred");
        }
    }

    private OtpResponse handleOtpResponse(CloseableHttpResponse response) throws IOException {
        int statusCode = response.getStatusLine().getStatusCode();
        logger.infof("OTP API Response status code: %d", statusCode);

        HttpEntity entity = response.getEntity();
        if (entity != null) {
            String responseString = EntityUtils.toString(entity, StandardCharsets.UTF_8);
            logger.infof("OTP API Response: %s", responseString);

            if (responseString.isEmpty()) {
                logger.warn("OTP API Response string is empty");
                return OtpResponse.error("EMPTY_RESPONSE", "Empty response from OTP API");
            }

            try {
                com.fasterxml.jackson.databind.JsonNode jsonResponse = mapper.readTree(responseString);

                String code = getTextSafely(jsonResponse, "code");
                String message = getTextSafely(jsonResponse, "message");

                logger.infof("OTP API Response - Code: %s, Message: %s", code, message);

                // Use the centralized success code check
                if (isSuccessCode(code)) {
                    logger.infof("OTP API call successful with code: %s", code);
                    return OtpResponse.success(code, message);
                } else {
                    logger.warnf("OTP API call failed with code: %s", code);
                    return OtpResponse.error(code, message);
                }

            } catch (Exception e) {
                logger.error("Error parsing OTP API JSON response", e);
                return OtpResponse.error("PARSE_ERROR", "Failed to parse OTP API response");
            }
        } else {
            logger.warn("OTP API response entity is null");
            return OtpResponse.error("NULL_RESPONSE", "Null response from OTP API");
        }
    }

    private boolean isSuccessCode(String code) {
        boolean isSuccess = SUCCESS_CODES.contains(code);
        logger.infof("Checking success code: '%s' -> %s", code, isSuccess);
        return isSuccess;
    }

    private String getTextSafely(com.fasterxml.jackson.databind.JsonNode node, String fieldName) {
        com.fasterxml.jackson.databind.JsonNode field = node.get(fieldName);
        return (field != null) ? field.asText("") : "";
    }
}
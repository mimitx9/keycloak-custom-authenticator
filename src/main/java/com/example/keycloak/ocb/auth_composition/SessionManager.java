package com.example.keycloak.ocb.auth_composition;

import org.jboss.logging.Logger;
import org.keycloak.sessions.AuthenticationSessionModel;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public class SessionManager {
    private static final Logger logger = Logger.getLogger(SessionManager.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    // Session keys
    public static final String AUTH_STATE = "AUTH_STATE";
    public static final String EXTERNAL_USERNAME = "EXTERNAL_USERNAME";
    public static final String EXTERNAL_PASSWORD = "EXTERNAL_PASSWORD";
    public static final String TRANSACTION_ID = "TRANSACTION_ID";
    public static final String USER_ID = "USER_ID";
    public static final String CUSTOMER_NUMBER = "CUSTOMER_NUMBER";
    public static final String USER_INFO_JSON = "USER_INFO_JSON";
    public static final String EXT_API_RESPONSE_CODE = "EXT_API_RESPONSE_CODE";
    public static final String EXT_API_RESPONSE_MESSAGE = "EXT_API_RESPONSE_MESSAGE";
    public static final String EXT_API_SUCCESS = "EXT_API_SUCCESS";
    public static final String OTP_API_RESPONSE_CODE = "OTP_API_RESPONSE_CODE";
    public static final String OTP_API_RESPONSE_MESSAGE = "OTP_API_RESPONSE_MESSAGE";
    public static final String OTP_API_SUCCESS = "OTP_API_SUCCESS";
    public static final String OTP_VERIFY_RESPONSE_CODE = "OTP_VERIFY_RESPONSE_CODE";
    public static final String OTP_VERIFY_RESPONSE_MESSAGE = "OTP_VERIFY_RESPONSE_MESSAGE";
    public static final String OTP_VERIFY_SUCCESS = "OTP_VERIFY_SUCCESS";

    // Auth states
    public static final String STATE_CREDENTIALS_VERIFIED = "CREDENTIALS_VERIFIED";
    public static final String STATE_OTP_SENT = "OTP_SENT";

    public static class SessionData {
        private String authState;
        private String username;
        private String transactionId;
        private String userId;
        private String customerNumber;
        private Map<String, String> userInfo;

        // Getters and setters
        public String getAuthState() { return authState; }
        public void setAuthState(String authState) { this.authState = authState; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getCustomerNumber() { return customerNumber; }
        public void setCustomerNumber(String customerNumber) { this.customerNumber = customerNumber; }

        public Map<String, String> getUserInfo() { return userInfo; }
        public void setUserInfo(Map<String, String> userInfo) { this.userInfo = userInfo; }
    }

    public static SessionData loadSessionData(AuthenticationSessionModel session) {
        try {
            logger.info("Loading session data");

            SessionData data = new SessionData();
            data.setAuthState(session.getAuthNote(AUTH_STATE));
            data.setUsername(session.getAuthNote(EXTERNAL_USERNAME));
            data.setTransactionId(session.getAuthNote(TRANSACTION_ID));
            data.setUserId(session.getAuthNote(USER_ID));
            data.setCustomerNumber(session.getAuthNote(CUSTOMER_NUMBER));

            String userInfoJson = session.getAuthNote(USER_INFO_JSON);
            if (userInfoJson != null && !userInfoJson.isEmpty()) {
                Map<String, String> userInfo = mapper.readValue(userInfoJson, Map.class);
                data.setUserInfo(userInfo);
            }

            logger.infof("Loaded session data - State: %s, Username: %s, TransactionId: %s, UserId: %s, CustomerNumber: %s",
                    data.getAuthState(), data.getUsername(), data.getTransactionId(),
                    data.getUserId(), data.getCustomerNumber());

            return data;

        } catch (Exception e) {
            logger.error("Error loading session data", e);
            return new SessionData();
        }
    }

    public static boolean hasRequiredOtpData(AuthenticationSessionModel session) {
        String transactionId = session.getAuthNote(TRANSACTION_ID);
        String userId = session.getAuthNote(USER_ID);
        String customerNumber = session.getAuthNote(CUSTOMER_NUMBER);

        boolean hasData = transactionId != null && !transactionId.isEmpty()
                && userId != null && !userId.isEmpty()
                && customerNumber != null && !customerNumber.isEmpty();

        logger.infof("Checking OTP data - TransactionId: %s, UserId: %s, CustomerNumber: %s, HasData: %s",
                transactionId, userId, customerNumber, hasData);

        return hasData;
    }

    public static void clearSession(AuthenticationSessionModel session) {
        logger.info("Clearing all session data");

        String[] allKeys = {
                AUTH_STATE, EXTERNAL_USERNAME, EXTERNAL_PASSWORD, TRANSACTION_ID,
                USER_ID, CUSTOMER_NUMBER, USER_INFO_JSON, EXT_API_RESPONSE_CODE,
                EXT_API_RESPONSE_MESSAGE, EXT_API_SUCCESS, OTP_API_RESPONSE_CODE,
                OTP_API_RESPONSE_MESSAGE, OTP_API_SUCCESS, OTP_VERIFY_RESPONSE_CODE,
                OTP_VERIFY_RESPONSE_MESSAGE, OTP_VERIFY_SUCCESS
        };

        for (String key : allKeys) {
            session.removeAuthNote(key);
        }

        logger.info("Session cleared successfully");
    }

    public static void logSessionState(AuthenticationSessionModel session, String context) {
        logger.infof("=== Session State (%s) ===", context);
        logger.infof("AUTH_STATE: %s", session.getAuthNote(AUTH_STATE));
        logger.infof("EXTERNAL_USERNAME: %s", session.getAuthNote(EXTERNAL_USERNAME));
        logger.infof("TRANSACTION_ID: %s", session.getAuthNote(TRANSACTION_ID));
        logger.infof("USER_ID: %s", session.getAuthNote(USER_ID));
        logger.infof("CUSTOMER_NUMBER: %s", session.getAuthNote(CUSTOMER_NUMBER));
        logger.infof("USER_INFO_JSON: %s", session.getAuthNote(USER_INFO_JSON) != null ? "Present" : "null");
        logger.info("=== End Session State ===");
    }
}
package com.example.keycloak.util;

import org.infinispan.Cache;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import java.io.Serializable;

public class OTPRequestManager {

    private static final Logger logger = Logger.getLogger(OTPRequestManager.class);

    private static final String CACHE_NAME = "otpBizconnectFailCount";
    private static final String OTP_REQ_PREFIX = "otpReq_";
    private static final String OTP_COOLDOWN_PREFIX = "otpCool_";

    private static final int MAX_REQUESTS_PER_HOUR = 5;
    private static final long COOLDOWN_MS = 30 * 1000L; // 30 seconds
    private static final long RESET_PERIOD_MS = 60 * 60 * 1000L; // 1 hour

    public static boolean canRequestOTP(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, OTPRequestData> cache = getCache(context);
            String cacheKey = OTP_REQ_PREFIX + user.getUsername();

            OTPRequestData requestData = cache.get(cacheKey);
            if (requestData == null) {
                return true;
            }

            long currentTime = System.currentTimeMillis();
            if (requestData.getResetTime() > 0 &&
                    currentTime - requestData.getResetTime() >= RESET_PERIOD_MS) {

                logger.infof("Resetting OTP request count for user: %s", user.getUsername());
                cache.remove(cacheKey);
                return true;
            }

            boolean canRequest = requestData.getRequestCount() < MAX_REQUESTS_PER_HOUR;
            logger.debugf("OTP request check for user %s: count=%d, canRequest=%s",
                    user.getUsername(), requestData.getRequestCount(), canRequest);

            return canRequest;

        } catch (Exception e) {
            logger.warnf("Cache error during OTP request check, allowing request: %s", e.getMessage());
            return true;
        }
    }

    public static void incrementOTPRequestCount(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, OTPRequestData> cache = getCache(context);
            String cacheKey = OTP_REQ_PREFIX + user.getUsername();

            OTPRequestData requestData = cache.get(cacheKey);
            if (requestData == null) {
                requestData = new OTPRequestData();
            }

            long currentTime = System.currentTimeMillis();

            if (requestData.getRequestCount() == 0) {
                requestData.setResetTime(currentTime);
            }

            requestData.incrementCount();
            cache.put(cacheKey, requestData);

            logger.infof("OTP request count incremented to %d for user: %s",
                    requestData.getRequestCount(), user.getUsername());

        } catch (Exception e) {
            logger.warnf("Cache error during OTP increment (non-critical): %s", e.getMessage());
        }
    }

    public static boolean canResendOTP(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();

            Long lastSentTime = cache.get(cacheKey);
            if (lastSentTime == null) {
                return true;
            }

            long elapsed = System.currentTimeMillis() - lastSentTime;
            boolean canResend = elapsed >= COOLDOWN_MS;

            logger.debugf("OTP resend check for user %s: elapsed=%dms, canResend=%s",
                    user.getUsername(), elapsed, canResend);

            return canResend;

        } catch (Exception e) {
            logger.warnf("Cache error during resend check, allowing resend: %s", e.getMessage());
            return true;
        }
    }

    public static long getResendCooldownRemaining(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();

            Long lastSentTime = cache.get(cacheKey);
            if (lastSentTime == null) {
                return 0;
            }

            long elapsed = System.currentTimeMillis() - lastSentTime;
            return Math.max(0, (COOLDOWN_MS - elapsed) / 1000);

        } catch (Exception e) {
            logger.warnf("Cache error during cooldown check, returning 0: %s", e.getMessage());
            return 0;
        }
    }

    public static void recordOTPSent(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();

            long currentTime = System.currentTimeMillis();
            cache.put(cacheKey, currentTime);

            logger.infof("OTP sent time recorded for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.warnf("Cache error during OTP sent recording (non-critical): %s", e.getMessage());
        }
    }

    public static void clearOTPSentTime(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();
            cache.remove(cacheKey);

            logger.infof("OTP sent time cleared for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.warnf("Cache error during OTP sent time clearing (non-critical): %s", e.getMessage());
        }
    }

    public static int getRemainingRequests(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, OTPRequestData> cache = getCache(context);
            String cacheKey = OTP_REQ_PREFIX + user.getUsername();

            OTPRequestData requestData = cache.get(cacheKey);
            if (requestData == null) {
                return MAX_REQUESTS_PER_HOUR;
            }

            long currentTime = System.currentTimeMillis();

            // Check if reset period has passed
            if (requestData.getResetTime() > 0 &&
                    currentTime - requestData.getResetTime() >= RESET_PERIOD_MS) {
                return MAX_REQUESTS_PER_HOUR;
            }

            return Math.max(0, MAX_REQUESTS_PER_HOUR - requestData.getRequestCount());

        } catch (Exception e) {
            logger.warnf("Cache error during remaining requests check, returning max: %s", e.getMessage());
            return MAX_REQUESTS_PER_HOUR;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> Cache<String, T> getCache(AuthenticationFlowContext context) {
        InfinispanConnectionProvider provider = context.getSession()
                .getProvider(InfinispanConnectionProvider.class);
        return provider.getCache(CACHE_NAME);
    }

    public static void clearUserOTPData(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Object> cache = getCache(context);
            String reqCacheKey = OTP_REQ_PREFIX + user.getUsername();
            String cooldownCacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();

            cache.remove(reqCacheKey);
            cache.remove(cooldownCacheKey);

            logger.infof("Cleared all OTP cache data for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.warnf("Cache error during OTP data clearing (non-critical): %s", e.getMessage());
        }
    }

    public static class OTPRequestData implements Serializable {
        private static final long serialVersionUID = 1L;

        private int requestCount = 0;
        private long resetTime = 0;

        public int getRequestCount() {
            return requestCount;
        }

        public void setRequestCount(int requestCount) {
            this.requestCount = requestCount;
        }

        public void incrementCount() {
            this.requestCount++;
        }

        public long getResetTime() {
            return resetTime;
        }

        public void setResetTime(long resetTime) {
            this.resetTime = resetTime;
        }

        public void reset() {
            this.requestCount = 0;
            this.resetTime = 0;
        }

        @Override
        public String toString() {
            return "OTPRequestData{" +
                    "requestCount=" + requestCount +
                    ", resetTime=" + resetTime +
                    '}';
        }
    }
}
package com.example.keycloak.util;

import org.infinispan.Cache;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

import java.io.Serializable;

public class OTPRequestManager {

    private static final Logger logger = Logger.getLogger(OTPRequestManager.class);
    private static final String OTP_SENT_TIME_PREFIX = "otpSentTime_";
    private static final String CACHE_NAME = "otpBizconnectFailCount";
    private static final String OTP_REQ_PREFIX = "otpReq_";
    private static final String OTP_COOLDOWN_PREFIX = "otpCool_";

    private static final long DEFAULT_OTP_VALIDITY_MS = 3 * 60 * 1000L;
    private static final long DEFAULT_COOLDOWN_MS = 30 * 1000L;
    private static final long DEFAULT_RESET_PERIOD_MS = 60 * 60 * 1000L;
    private static final int DEFAULT_MAX_REQUESTS_PER_HOUR = 5;

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
                    currentTime - requestData.getResetTime() >= getResetPeriodMs(context)) {

                logger.infof("Resetting OTP request count for user: %s", user.getUsername());
                cache.remove(cacheKey);
                return true;
            }

            int maxRequests = getMaxRequestsPerPeriod(context);
            boolean canRequest = requestData.getRequestCount() < maxRequests;
            logger.debugf("OTP request check for user %s: count=%d, max=%d, canRequest=%s",
                    user.getUsername(), requestData.getRequestCount(), maxRequests, canRequest);

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
            long cooldownMs = getCooldownMs(context);
            boolean canResend = elapsed >= cooldownMs;

            logger.debugf("OTP resend check for user %s: elapsed=%dms, cooldown=%dms, canResend=%s",
                    user.getUsername(), elapsed, cooldownMs, canResend);

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
            long cooldownMs = getCooldownMs(context);
            return Math.max(0, (cooldownMs - elapsed) / 1000);

        } catch (Exception e) {
            logger.warnf("Cache error during cooldown check, returning 0: %s", e.getMessage());
            return 0;
        }
    }

    public static void recordOTPSent(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cooldownKey = OTP_COOLDOWN_PREFIX + user.getUsername();
            String timeKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            long currentTime = System.currentTimeMillis();
            cache.put(cooldownKey, currentTime);
            cache.put(timeKey, currentTime);

            logger.infof("OTP sent time recorded for user: %s", user.getUsername());

        } catch (Exception e) {
            logger.warnf("Cache error during OTP sent recording (non-critical): %s", e.getMessage());
        }
    }

    public static void clearOTPSentTime(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cooldownKey = OTP_COOLDOWN_PREFIX + user.getUsername();
            String timeKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            cache.remove(cooldownKey);
            cache.remove(timeKey);

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
                return getMaxRequestsPerPeriod(context);
            }

            long currentTime = System.currentTimeMillis();

            if (requestData.getResetTime() > 0 &&
                    currentTime - requestData.getResetTime() >= getResetPeriodMs(context)) {
                return getMaxRequestsPerPeriod(context);
            }

            int maxRequests = getMaxRequestsPerPeriod(context);
            return Math.max(0, maxRequests - requestData.getRequestCount());
        } catch (Exception e) {
            logger.warnf("Cache error during remaining requests check, returning max: %s", e.getMessage());
            return getMaxRequestsPerPeriod(context);
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
            String timeCacheKey = OTP_SENT_TIME_PREFIX + user.getUsername();
            Cache<String, Object> cache = getCache(context);
            String reqCacheKey = OTP_REQ_PREFIX + user.getUsername();
            String cooldownCacheKey = OTP_COOLDOWN_PREFIX + user.getUsername();
            cache.remove(timeCacheKey);
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

    public static boolean isOTPValid(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            Long sentTime = cache.get(cacheKey);
            if (sentTime == null) {
                return false;
            }

            long currentTime = System.currentTimeMillis();
            long validityMs = getOTPValidityMs(context);
            boolean isValid = (currentTime - sentTime) <= validityMs;

            if (!isValid) {
                cache.remove(cacheKey);
                logger.infof("OTP expired for user: %s", user.getUsername());
            }

            return isValid;

        } catch (Exception e) {
            logger.warnf("Cache error during OTP validity check: %s", e.getMessage());
            return true;
        }
    }

    public static long getOTPRemainingTime(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            Long sentTime = cache.get(cacheKey);
            if (sentTime == null) {
                return 0;
            }

            long currentTime = System.currentTimeMillis();
            long elapsed = currentTime - sentTime;

            long validityMs = getOTPValidityMs(context);
            return Math.max(0, (validityMs - elapsed) / 1000);

        } catch (Exception e) {
            logger.warnf("Cache error during OTP remaining time check: %s", e.getMessage());
            return 0;
        }
    }

    public static long getOTPRemainingSeconds(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            Long sentTime = cache.get(cacheKey);
            if (sentTime == null) {
                return 0;
            }

            long currentTime = System.currentTimeMillis();
            long elapsed = currentTime - sentTime;

            long validityMs = getOTPValidityMs(context);
            long remainingMs = validityMs - elapsed;

            if (remainingMs <= 0) {
                return 0;
            }

            return remainingMs / 1000;

        } catch (Exception e) {
            logger.warnf("Cache error during OTP remaining time check: %s", e.getMessage());
            return getOTPValidityMs(context) / 1000;
        }
    }

    public static long getOTPSentTime(AuthenticationFlowContext context, UserModel user) {
        try {
            Cache<String, Long> cache = getCache(context);
            String cacheKey = OTP_SENT_TIME_PREFIX + user.getUsername();

            Long sentTime = cache.get(cacheKey);
            return sentTime != null ? sentTime : 0;

        } catch (Exception e) {
            logger.warnf("Cache error during OTP sent time retrieval: %s", e.getMessage());
            return 0;
        }
    }

    private static long getOTPValidityMs(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        try {
            String seconds = getConfigValue(config, "otpValiditySeconds", "180");
            return Long.parseLong(seconds) * 1000L;
        } catch (NumberFormatException e) {
            logger.warnf("Invalid OTP validity config, using default: %s", e.getMessage());
            return DEFAULT_OTP_VALIDITY_MS;
        }
    }

    private static long getCooldownMs(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        try {
            String seconds = getConfigValue(config, "otpResendCooldownSeconds", "30");
            return Long.parseLong(seconds) * 1000L;
        } catch (NumberFormatException e) {
            logger.warnf("Invalid cooldown config, using default: %s", e.getMessage());
            return DEFAULT_COOLDOWN_MS;
        }
    }

    private static long getResetPeriodMs(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        try {
            String minutes = getConfigValue(config, "otpRequestResetPeriodMinutes", "60");
            return Long.parseLong(minutes) * 60 * 1000L; // Convert to milliseconds
        } catch (NumberFormatException e) {
            logger.warnf("Invalid reset period config, using default: %s", e.getMessage());
            return DEFAULT_RESET_PERIOD_MS;
        }
    }

    private static int getMaxRequestsPerPeriod(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        try {
            String maxRequests = getConfigValue(config, "maxOtpRequestsPerPeriod", "5");
            return Integer.parseInt(maxRequests);
        } catch (NumberFormatException e) {
            logger.warnf("Invalid max requests config, using default: %s", e.getMessage());
            return DEFAULT_MAX_REQUESTS_PER_HOUR;
        }
    }

    private static String getConfigValue(AuthenticatorConfigModel config, String key, String defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        return config.getConfig().getOrDefault(key, defaultValue);
    }
}
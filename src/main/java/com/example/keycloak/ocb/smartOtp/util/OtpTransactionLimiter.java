package com.example.keycloak.ocb.smartOtp.util;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;


public class OtpTransactionLimiter {
    private static final Logger logger = Logger.getLogger(OtpTransactionLimiter.class);

    private final int maxOtpPerDay;
    private final KeycloakSession session;
    private final RealmModel realm;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final String OTP_COUNT_PREFIX = "otp_count_";

    public OtpTransactionLimiter(KeycloakSession session, RealmModel realm, int maxOtpPerDay) {
        this.session = session;
        this.realm = realm;
        this.maxOtpPerDay = maxOtpPerDay;
    }

    public boolean canCreateOtpTransaction(String username) {
        try {
            String today = LocalDate.now().format(DATE_FORMATTER);
            String otpCountAttr = OTP_COUNT_PREFIX + today;

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                return true;
            }

            // Cleanup old OTP count attributes before checking today's count
            cleanupOldOtpCountAttributes(user, today);

            String countStr = user.getFirstAttribute(otpCountAttr);
            int todayCount = 0;

            if (countStr != null && !countStr.isEmpty()) {
                try {
                    todayCount = Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    logger.warnf("Invalid OTP count format for user %s: %s, resetting to 0", username, countStr);
                    // Reset invalid count to 0
                    user.setSingleAttribute(otpCountAttr, "0");
                }
            }

            boolean canCreate = todayCount < maxOtpPerDay;
            logger.infof("User %s: %d/%d OTP today, can create: %s",
                    username, todayCount, maxOtpPerDay, canCreate);

            return canCreate;

        } catch (Exception e) {
            logger.error("Error checking OTP limit for user: " + username, e);
            return false;
        }
    }

    public void recordOtpTransaction(String username) {
        try {
            String today = LocalDate.now().format(DATE_FORMATTER);
            String otpCountAttr = OTP_COUNT_PREFIX + today;

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                logger.warn("Cannot record OTP - user not found: " + username);
                return;
            }

            // Cleanup old OTP count attributes before recording new one
            cleanupOldOtpCountAttributes(user, today);

            String countStr = user.getFirstAttribute(otpCountAttr);
            int currentCount = 0;

            if (countStr != null && !countStr.isEmpty()) {
                try {
                    currentCount = Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    logger.warnf("Invalid OTP count format for user %s: %s, resetting to 0", username, countStr);
                }
            }

            int newCount = currentCount + 1;
            user.setSingleAttribute(otpCountAttr, String.valueOf(newCount));

            logger.infof("Recorded OTP for user %s: %d -> %d", username, currentCount, newCount);

        } catch (Exception e) {
            logger.error("Error recording OTP transaction for user: " + username, e);
        }
    }

    /**
     * Cleanup old OTP count attributes that are not for today
     * @param user The user model
     * @param today Today's date in yyyyMMdd format
     */
    private void cleanupOldOtpCountAttributes(UserModel user, String today) {
        try {
            String todayAttr = OTP_COUNT_PREFIX + today;

            // Get all user attributes that start with OTP_COUNT_PREFIX
            List<String> otpCountAttributes = user.getAttributes().keySet().stream()
                    .filter(attr -> attr.startsWith(OTP_COUNT_PREFIX))
                    .filter(attr -> !attr.equals(todayAttr)) // Exclude today's attribute
                    .collect(Collectors.toList());

            if (!otpCountAttributes.isEmpty()) {
                logger.infof("Cleaning up %d old OTP count attributes for user %s: %s",
                        otpCountAttributes.size(), user.getUsername(), otpCountAttributes);

                // Remove old OTP count attributes
                for (String oldAttr : otpCountAttributes) {
                    user.removeAttribute(oldAttr);
                }

                logger.infof("Successfully cleaned up old OTP count attributes for user %s", user.getUsername());
            }

        } catch (Exception e) {
            logger.error("Error cleaning up old OTP count attributes for user: " + user.getUsername(), e);
            // Don't throw exception here, just log the error so it doesn't break the main flow
        }
    }

    /**
     * Manual cleanup method that can be called to clean all old OTP count attributes
     * This could be useful for maintenance tasks
     * @param username The username to cleanup
     */
    public void forceCleanupOldOtpCounts(String username) {
        try {
            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                logger.warn("Cannot cleanup OTP counts - user not found: " + username);
                return;
            }

            String today = LocalDate.now().format(DATE_FORMATTER);
            cleanupOldOtpCountAttributes(user, today);

        } catch (Exception e) {
            logger.error("Error in force cleanup for user: " + username, e);
        }
    }

    /**
     * Get current OTP count for today
     * @param username The username
     * @return Current OTP count for today, or 0 if not found
     */
    public int getCurrentOtpCount(String username) {
        try {
            String today = LocalDate.now().format(DATE_FORMATTER);
            String otpCountAttr = OTP_COUNT_PREFIX + today;

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                return 0;
            }

            String countStr = user.getFirstAttribute(otpCountAttr);
            if (countStr != null && !countStr.isEmpty()) {
                try {
                    return Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    logger.warnf("Invalid OTP count format for user %s: %s", username, countStr);
                    return 0;
                }
            }

            return 0;

        } catch (Exception e) {
            logger.error("Error getting current OTP count for user: " + username, e);
            return 0;
        }
    }
}
package com.example.keycloak.ocb.auth;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;


public class OtpTransactionLimiter {
    private static final Logger logger = Logger.getLogger(OtpTransactionLimiter.class);

    private final int maxOtpPerDay;
    private final KeycloakSession session;
    private final RealmModel realm;
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    public OtpTransactionLimiter(KeycloakSession session, RealmModel realm, int maxOtpPerDay) {
        this.session = session;
        this.realm = realm;
        this.maxOtpPerDay = maxOtpPerDay;
    }

    public boolean canCreateOtpTransaction(String username) {
        try {
            String today = LocalDate.now().format(DATE_FORMATTER);
            String otpCountAttr = "otp_count_" + today;

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                return true;
            }

            String countStr = user.getFirstAttribute(otpCountAttr);
            int todayCount = 0;

            if (countStr != null && !countStr.isEmpty()) {
                try {
                    todayCount = Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    logger.warnf("Invalid OTP count format for user %s: %s, resetting to 0", username, countStr);
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
            String otpCountAttr = "otp_count_" + today;

            UserModel user = session.users().getUserByUsername(realm, username);
            if (user == null) {
                logger.warn("Cannot record OTP - user not found: " + username);
                return;
            }

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
}
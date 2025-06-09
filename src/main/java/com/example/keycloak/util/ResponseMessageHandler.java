package com.example.keycloak.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

public class ResponseMessageHandler {

    private static final String CONTACT_INFO = "Danh sách Trung tâm VPBank SME: Xem tại đây\nTổng đài hỗ trợ: 1900 234 568 #2";

    public static Map<String, Object> createOTPLockoutResponse(long lockedAt, int lockDuration, int attemptCount) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("lockedAt", lockedAt);
        responseData.put("lockDuration", lockDuration);
        responseData.put("attemptCount", attemptCount);
        int lockDurationMinutes = lockDuration / 60;
        responseData.put("lockDurationMinutes", lockDurationMinutes);
        long unlockTime = lockedAt + (lockDuration * 1000L);
        responseData.put("unlockTime", unlockTime);
        String unlockTimeFormatted = getUnlockTime(lockedAt, lockDuration);
        responseData.put("unlockTimeFormatted", unlockTimeFormatted);
        String message = createLockoutMessage(lockDuration);
        responseData.put("message", message);
        responseData.put("contactInfo", CONTACT_INFO);

        return responseData;
    }

    public static Map<String, Object> createOTPInvalidResponse() {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "Mã OTP không hợp lệ");
        return responseData;
    }

    public static Map<String, Object> createOTPSentResponse(String phone) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "VPBank đã gửi mã OTP đến số điện thoại " + maskPhone(phone) + ". Vui lòng nhập mã OTP này để đăng nhập.");
        responseData.put("phone", maskPhone(phone));
        return responseData;
    }

    public static String maskPhone(String phone) {
        if (phone == null || phone.length() < 6) {
            return phone;
        }
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 3);
    }

    public static Map<String, Object> createResendCooldownResponse(long cooldownSeconds) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("cooldownSeconds", cooldownSeconds);
        responseData.put("resendCooldown", cooldownSeconds);
        responseData.put("message", "Yêu cầu gửi lại OTP không thành công. Vui lòng thử lại sau " + cooldownSeconds + " giây.");
        responseData.put("disableResendButton", true);
        return responseData;
    }

    public static Map<String, Object> createOTPSendFailedResponse() {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "Yêu cầu gửi lại OTP không thành công. Vui lòng thử lại sau 30 giây.");
        responseData.put("contactInfo", CONTACT_INFO);
        return responseData;
    }

    public static Map<String, Object> createOTPRequestLimitResponse() {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "Quý khách đề nghị gửi SMS OTP quá số lần cho phép, vui lòng thử lại sau");
        responseData.put("contactInfo", CONTACT_INFO);
        return responseData;
    }

    private static String getUnlockTime(long lockedAt, int lockDuration) {
        try {
            long unlockTimeMs = lockedAt + (lockDuration * 1000L);
            LocalDateTime unlockTime = LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(unlockTimeMs),
                    ZoneId.systemDefault()
            );
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm dd/MM/yyyy");
            return unlockTime.format(formatter);
        } catch (Exception e) {
            return "";
        }
    }

    private static String createLockoutMessage(int lockDuration) {
        int minutes = lockDuration / 60;
        int hours = minutes / 60;

        String timeText;
        if (hours >= 24) {
            timeText = "24 giờ";
        } else if (hours > 0) {
            timeText = hours + " giờ";
        } else {
            timeText = minutes + " phút";
        }

        if (hours >= 24) {
            return "Tài khoản của Quý khách đã bị khóa do nhập sai OTP nhiều lần. " +
                    "Tài khoản sẽ tự động mở lại lúc {getUnlockTime(responseData?.lockedAt, responseData?.lockDuration)}. " +
                    "Quý khách có thể truy cập {unlockUrl} để yêu cầu mở khóa.";
        } else {
            return "Tài khoản của Quý khách bị khóa do nhập sai OTP nhiều lần. " +
                    "Vui lòng thử lại sau " + timeText + ".";
        }
    }
}
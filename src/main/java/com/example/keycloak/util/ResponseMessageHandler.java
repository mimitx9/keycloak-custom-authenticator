package com.example.keycloak.util;

import java.util.HashMap;
import java.util.Map;

public class ResponseMessageHandler {

    private static final String CONTACT_INFO = "Danh sách Trung tâm VPBank SME: Xem tại đây\nTổng đài hỗ trợ: 1900 234 568 #2";

    public static Map<String, Object> createLoginLockoutResponse(long lockedAt, int lockDuration, int attemptCount) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("lockedAt", lockedAt);
        responseData.put("lockDuration", lockDuration);
        responseData.put("attemptCount", attemptCount);

        long unlockTime = lockedAt + (lockDuration * 1000L);
        responseData.put("unlockTime", unlockTime);

        int lockDurationMinutes = lockDuration / 60;
        String message = createLoginLockoutMessage(lockDurationMinutes);
        responseData.put("message", message);
        responseData.put("contactInfo", CONTACT_INFO);

        return responseData;
    }

    // Message cho login lockout
    private static String createLoginLockoutMessage(int lockDurationMinutes) {
        if (lockDurationMinutes >= 60) {
            int hours = lockDurationMinutes / 60;
            return "Tài khoản của Quý khách bị khóa do đăng nhập sai nhiều lần. " +
                    "Vui lòng thử lại sau " + hours + " giờ.";
        } else {
            return "Tài khoản của Quý khách bị khóa do đăng nhập sai nhiều lần. " +
                    "Vui lòng thử lại sau " + lockDurationMinutes + " phút.";
        }
    }

    public static Map<String, Object> createOTPLockoutResponse(long lockedAt, int lockDuration, int attemptCount) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("lockedAt", lockedAt);
        responseData.put("lockDuration", lockDuration);
        responseData.put("attemptCount", attemptCount);

        // Thêm lockDurationMinutes cho frontend hiển thị "${lockDurationMinutes} phút"
        int lockDurationMinutes = lockDuration / 60;
        responseData.put("lockDurationMinutes", lockDurationMinutes);

        // Thêm unlockTime cho frontend
        long unlockTime = lockedAt + (lockDuration * 1000L);
        responseData.put("unlockTime", unlockTime);

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

        // Thêm thông tin OTP validity cho frontend countdown
        long currentTime = System.currentTimeMillis();
        responseData.put("otpSentAt", currentTime);
        responseData.put("otpValiditySeconds", 180); // Thời gian tối đa: 3 phút
        responseData.put("otpRemainingSeconds", 180); // Thời gian valid thực tế: lần đầu là 180s

        return responseData;
    }

    // Method cho OTP form khi refresh trang
    public static Map<String, Object> createOTPFormResponse(String phone, long otpSentAt, long remainingSeconds) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "Vui lòng nhập mã OTP đã được gửi đến số điện thoại " + maskPhone(phone) + ".");
        responseData.put("phone", maskPhone(phone));
        responseData.put("otpSentAt", otpSentAt);
        responseData.put("otpValiditySeconds", 180); // Thời gian tối đa: 3 phút
        responseData.put("otpRemainingSeconds", remainingSeconds); // Thời gian valid thực tế: còn lại bao nhiêu

        return responseData;
    }

    // THÊM MỚI: Response cho OTP expired
    public static Map<String, Object> createOTPExpiredResponse() {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("message", "Mã OTP đã hết hạn. Vui lòng yêu cầu gửi lại OTP mới.");
        responseData.put("otpValiditySeconds", 180); // Thời gian tối đa: 3 phút
        responseData.put("otpRemainingSeconds", 0);   // Thời gian valid thực tế: đã hết (0s)
        responseData.put("otpExpired", true);
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
        responseData.put("resendCooldown", cooldownSeconds); // Thêm field này cho frontend
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

    // Cập nhật message theo format yêu cầu
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
                    "Tài khoản sẽ tự động mở lại sau " + timeText + ". " +
                    "Quý khách có thể sử dụng chức năng mở khóa để mở khóa ngay lập tức.";
        } else {
            return "Tài khoản của Quý khách bị khóa do nhập sai OTP nhiều lần. " +
                    "Vui lòng thử lại sau " + timeText + ".";
        }
    }
}
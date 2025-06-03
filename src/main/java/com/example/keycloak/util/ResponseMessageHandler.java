package com.example.keycloak.util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class ResponseMessageHandler {

    private static final String CONTACT_INFO = "Danh sách Trung tâm VPBank SME: Xem tại đây\nTổng đài hỗ trợ: 1900 234 568 #2";


    public static Map<String, Object> createOTPLockoutResponse(long lockedAt, int lockDuration, int attemptCount) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("lockedAt", lockedAt);
        responseData.put("lockDuration", lockDuration);
        responseData.put("attemptCount", attemptCount);

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
        responseData.put("message", "Vui lòng đợi " + cooldownSeconds + " giây trước khi gửi lại OTP");
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

    // Đơn giản hóa - chỉ tạo message text
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
                    "Quý khách có thể sử dụng chức năng mở khóa để mở khóa ngay lập tức. " +
                    "Vui lòng liên hệ VPBank SME gần nhất nếu cần hỗ trợ.";
        } else {
            return "Tài khoản của Quý khách bị khóa do nhập sai OTP nhiều lần. " +
                    "Vui lòng thử lại sau " + timeText + ".";
        }
    }
}
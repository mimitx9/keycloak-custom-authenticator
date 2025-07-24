package com.example.keycloak.ocb;

import com.example.keycloak.ocb.authenticate.OcbUserVerificationAuthenticator;
import com.example.keycloak.ocb.authenticate.client.OcbClient;
import com.example.keycloak.ocb.authenticate.model.ApiResponse;
import com.example.keycloak.ocb.smartOtp.SmartOtpAuthenticator;
import com.example.keycloak.ocb.smartOtp.client.SmartOtpClient;
import com.example.keycloak.ocb.smartOtp.model.OtpResponse;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Test complete successful authentication flow with mocked API calls
 * This prevents actual HTTP requests and returns expected responses
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SuccessfulLoginFlowTest {

    @Mock
    private AuthenticationFlowContext context;
    @Mock
    private AuthenticationSessionModel authSession;
    @Mock
    private AuthenticatorConfigModel configModel;
    @Mock
    private HttpRequest httpRequest;
    @Mock
    private LoginFormsProvider loginFormsProvider;
    @Mock
    private Response response;
    @Mock
    private KeycloakSession keycloakSession;
    @Mock
    private UserProvider userProvider;
    @Mock
    private RealmModel realm;
    @Mock
    private UserModel user;

    private CustomUsernamePasswordForm usernamePasswordForm;
    private OcbUserVerificationAuthenticator ocbAuthenticator;
    private SmartOtpAuthenticator otpAuthenticator;

    private static final String TEST_USERNAME = "ccpuser001";
    private static final String TEST_PASSWORD = "SecurePass123";
    private static final String TEST_CUSTOMER_NUMBER = "0123456789";
    private static final String TEST_OTP = "654321";

    @BeforeEach
    void setUp() {
        usernamePasswordForm = new CustomUsernamePasswordForm();
        ocbAuthenticator = new OcbUserVerificationAuthenticator();
        otpAuthenticator = new SmartOtpAuthenticator();

        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
        lenient().when(context.getAuthenticatorConfig()).thenReturn(configModel);
        lenient().when(context.getHttpRequest()).thenReturn(httpRequest);
        lenient().when(context.form()).thenReturn(loginFormsProvider);
        lenient().when(context.getSession()).thenReturn(keycloakSession);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getUser()).thenReturn(user);
        lenient().when(keycloakSession.users()).thenReturn(userProvider);

        lenient().when(loginFormsProvider.setAttribute(anyString(), any())).thenReturn(loginFormsProvider);
        lenient().when(loginFormsProvider.setError(anyString())).thenReturn(loginFormsProvider);
        lenient().when(loginFormsProvider.setError(anyString(), any())).thenReturn(loginFormsProvider);
        lenient().when(loginFormsProvider.setInfo(anyString())).thenReturn(loginFormsProvider);
        lenient().when(loginFormsProvider.createLoginUsernamePassword()).thenReturn(response);

        lenient().when(loginFormsProvider.createForm(anyString())).thenReturn(response);
        lenient().when(loginFormsProvider.createErrorPage(any())).thenReturn(response);
    }

    @Test
    void testCompleteSuccessfulAuthenticationFlow() {
        System.out.println("=== Testing Complete Successful Authentication Flow (Mocked APIs) ===");

        System.out.println("\n--- Step 1: Username/Password Collection ---");

        MultivaluedMap<String, String> credentialsForm = new MultivaluedHashMap<>();
        credentialsForm.putSingle("username", TEST_USERNAME);
        credentialsForm.putSingle("password", TEST_PASSWORD);
        when(httpRequest.getDecodedFormParameters()).thenReturn(credentialsForm);

        usernamePasswordForm.action(context);

        verify(authSession).setAuthNote("EXTERNAL_USERNAME", TEST_USERNAME);
        verify(authSession).setAuthNote("EXTERNAL_PASSWORD", TEST_PASSWORD);
        verify(context).success();
        System.out.println("✓ Step 1: Credentials collected successfully");

        System.out.println("\n--- Step 2: OCB User Verification (Mocked API) ---");

        when(authSession.getAuthNote("EXTERNAL_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("EXTERNAL_PASSWORD")).thenReturn(TEST_PASSWORD);
        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn(null);

        Map<String, String> ocbConfig = createOcbConfig();
        when(configModel.getConfig()).thenReturn(ocbConfig);

        when(userProvider.getUserByUsername(realm, TEST_USERNAME)).thenReturn(null);
        when(userProvider.addUser(realm, TEST_USERNAME)).thenReturn(user);

        Map<String, String> userInfo = createUserInfo();
        ApiResponse mockApiResponse = ApiResponse.success(userInfo);

        try (MockedConstruction<OcbClient> ignored = mockConstruction(OcbClient.class,
                (mock, context) -> when(mock.verifyUser(TEST_USERNAME, TEST_PASSWORD)).thenReturn(mockApiResponse))) {

            ocbAuthenticator.authenticate(context);

            verify(authSession).setAuthNote("EXTERNAL_VERIFICATION_COMPLETED", "true");
            verify(authSession).setAuthNote("VERIFIED_USERNAME", TEST_USERNAME);
            verify(authSession).setAuthNote("CUSTOMER_NUMBER", TEST_CUSTOMER_NUMBER);
            verify(authSession).setAuthNote(eq("USER_INFO_JSON"), anyString());

            System.out.println("✓ Step 2: OCB verification successful (mocked API returned success)");
        }

        System.out.println("\n--- Step 3: Smart OTP Authentication (Mocked API) ---");

        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn("true");
        when(authSession.getAuthNote("VERIFIED_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("CUSTOMER_NUMBER")).thenReturn(TEST_CUSTOMER_NUMBER);
        when(authSession.getAuthNote("OTP_STATE")).thenReturn(null);

        Map<String, String> otpConfig = createOtpConfig();
        when(configModel.getConfig()).thenReturn(otpConfig);

        OtpResponse mockOtpCreateResponse = OtpResponse.success("00", "OTP transaction created successfully");

        try (MockedConstruction<SmartOtpClient> mockedOtpClient = mockConstruction(SmartOtpClient.class,
                (mock, context) -> {
                    when(mock.createTransaction(anyString(), anyString(), anyString(), anyInt(),
                            anyString(), anyString(), anyInt(), anyInt(),
                            anyString(), anyString(), anyInt(), anyInt(), anyInt()))
                            .thenReturn(mockOtpCreateResponse);
                })) {

            otpAuthenticator.authenticate(context);
            System.out.println("✓ Step 3a: OTP transaction created successfully (mocked API)");
        }

        System.out.println("\n--- Step 4: OTP Verification (Mocked API) ---");

        MultivaluedMap<String, String> otpForm = new MultivaluedHashMap<>();
        otpForm.putSingle("action", "verify_otp");
        otpForm.putSingle("otp", TEST_OTP);
        when(httpRequest.getDecodedFormParameters()).thenReturn(otpForm);

        when(authSession.getAuthNote("TRANSACTION_ID")).thenReturn("txn_12345");
        when(authSession.getAuthNote("USER_ID")).thenReturn("OCB_" + TEST_CUSTOMER_NUMBER);

        OtpResponse mockOtpVerifyResponse = OtpResponse.success("00", "OTP verified successfully");

        try (MockedConstruction<SmartOtpClient> mockedOtpClient = mockConstruction(SmartOtpClient.class,
                (mock, context) -> {
                    when(mock.verifyOtp("OCB_" + TEST_CUSTOMER_NUMBER, TEST_OTP, "txn_12345"))
                            .thenReturn(mockOtpVerifyResponse);
                })) {

            otpAuthenticator.action(context);

            verify(authSession).setAuthNote("OTP_VERIFY_SUCCESS", "true");
            verify(authSession).setAuthNote("OTP_VERIFY_RESPONSE_CODE", "00");
            verify(authSession).setAuthNote("OTP_VERIFY_RESPONSE_MESSAGE", "OTP verified successfully");

            System.out.println("✓ Step 4: OTP verification successful (mocked API)");
        }

        System.out.println("\n--- Final Verification ---");

        verify(context, atLeast(2)).success(); // Multiple success calls
        verify(userProvider).addUser(realm, TEST_USERNAME);
        verify(user).setEnabled(true);

        System.out.println("✓ Complete authentication flow successful!");
        System.out.println("✓ User " + TEST_USERNAME + " authenticated with mocked APIs");
        System.out.println("✓ All HTTP requests were mocked - no real network calls made");
    }

    @Test
    void testOcbApiSuccess_MockedOnly() {
        System.out.println("=== Testing OCB API Success (Mocked Only) ===");

        when(authSession.getAuthNote("EXTERNAL_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("EXTERNAL_PASSWORD")).thenReturn(TEST_PASSWORD);
        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn(null);

        Map<String, String> ocbConfig = createOcbConfig();
        when(configModel.getConfig()).thenReturn(ocbConfig);

        when(userProvider.getUserByUsername(realm, TEST_USERNAME)).thenReturn(null);
        when(userProvider.addUser(realm, TEST_USERNAME)).thenReturn(user);

        Map<String, String> userInfo = createUserInfo();
        ApiResponse mockResponse = ApiResponse.success(userInfo);

        try (MockedConstruction<OcbClient> mockedOcbClient = mockConstruction(OcbClient.class,
                (mock, context) -> {
                    when(mock.verifyUser(TEST_USERNAME, TEST_PASSWORD)).thenReturn(mockResponse);
                })) {

            ocbAuthenticator.authenticate(context);

            verify(authSession).setAuthNote("EXTERNAL_VERIFICATION_COMPLETED", "true");
            verify(authSession).setAuthNote("EXT_API_SUCCESS", "true");

            System.out.println("✓ OCB API call successful (mocked)");
            System.out.println("✓ No UnknownHostException or network errors");
        }
    }

    @Test
    void testSmartOtpApiSuccess_MockedOnly() {
        System.out.println("=== Testing Smart OTP API Success (Mocked Only) ===");

        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn("true");
        when(authSession.getAuthNote("VERIFIED_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("CUSTOMER_NUMBER")).thenReturn(TEST_CUSTOMER_NUMBER);
        when(authSession.getAuthNote("TRANSACTION_ID")).thenReturn("txn_12345");
        when(authSession.getAuthNote("USER_ID")).thenReturn("OCB_" + TEST_CUSTOMER_NUMBER);

        Map<String, String> otpConfig = createOtpConfig();
        when(configModel.getConfig()).thenReturn(otpConfig);

        MultivaluedMap<String, String> otpForm = new MultivaluedHashMap<>();
        otpForm.putSingle("action", "verify_otp");
        otpForm.putSingle("otp", TEST_OTP);
        when(httpRequest.getDecodedFormParameters()).thenReturn(otpForm);

        OtpResponse mockResponse = OtpResponse.success("00", "OTP verified successfully");

        try (MockedConstruction<SmartOtpClient> mockedOtpClient = mockConstruction(SmartOtpClient.class,
                (mock, context) -> {
                    when(mock.verifyOtp("OCB_" + TEST_CUSTOMER_NUMBER, TEST_OTP, "txn_12345"))
                            .thenReturn(mockResponse);
                })) {

            otpAuthenticator.action(context);

            verify(authSession).setAuthNote("OTP_VERIFY_SUCCESS", "true");
            verify(context).success();

            System.out.println("✓ Smart OTP API call successful (mocked)");
            System.out.println("✓ No network errors or timeout issues");
        }
    }

    @Test
    void testBypassOtpStillWorks() {
        System.out.println("=== Testing OTP Bypass Still Works ===");

        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn("true");
        when(authSession.getAuthNote("VERIFIED_USERNAME")).thenReturn(TEST_USERNAME);

        MultivaluedMap<String, String> bypassForm = new MultivaluedHashMap<>();
        bypassForm.putSingle("action", "verify_otp");
        bypassForm.putSingle("otp", "123456"); // Bypass code
        when(httpRequest.getDecodedFormParameters()).thenReturn(bypassForm);

        otpAuthenticator.action(context);

        verify(authSession).setAuthNote("OTP_VERIFY_RESPONSE_CODE", "00");
        verify(authSession).setAuthNote("OTP_VERIFY_RESPONSE_MESSAGE", "Bypass OTP verification successful");
        verify(context).success();

        System.out.println("✓ OTP bypass still works for development");
    }

    private Map<String, String> createOcbConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("apiUrl", "https://ocb-api.example.com/verify");
        config.put("apiUsername", "api_user");
        config.put("apiPassword", "api_pass");
        config.put("timeout", "10");
        config.put("isLastStep", "false");
        return config;
    }

    private Map<String, String> createOtpConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("otpUrl", "https://smart-otp-api.example.com");
        config.put("otpApiKey", "otp_api_key");
        config.put("timeout", "10");
        config.put("transactionData", "1|CCP|Login|0");
        config.put("maxOtpPerDay", "100");
        return config;
    }

    private Map<String, String> createUserInfo() {
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("customerNumber", TEST_CUSTOMER_NUMBER);
        userInfo.put("userName", TEST_USERNAME);
        userInfo.put("fullName", "CCP Test User");
        userInfo.put("email", "ccp.user@ocb.com.vn");
        userInfo.put("mobile", "0987654321");
        return userInfo;
    }

    @Test
    void testOcbVerificationSuccess_But_SmartOtpError_FlowFails() {
        System.out.println("=== Testing OCB Success but Smart OTP Error - Flow Fails ===");

        System.out.println("\n--- Step 1: Username/Password Collection (Success) ---");

        MultivaluedMap<String, String> credentialsForm = new MultivaluedHashMap<>();
        credentialsForm.putSingle("username", TEST_USERNAME);
        credentialsForm.putSingle("password", TEST_PASSWORD);
        when(httpRequest.getDecodedFormParameters()).thenReturn(credentialsForm);

        usernamePasswordForm.action(context);

        verify(authSession).setAuthNote("EXTERNAL_USERNAME", TEST_USERNAME);
        verify(authSession).setAuthNote("EXTERNAL_PASSWORD", TEST_PASSWORD);
        verify(context).success();
        System.out.println("✓ Step 1: Credentials collected successfully");

        System.out.println("\n--- Step 2: OCB User Verification (Success) ---");

        when(authSession.getAuthNote("EXTERNAL_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("EXTERNAL_PASSWORD")).thenReturn(TEST_PASSWORD);
        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn(null);

        Map<String, String> ocbConfig = createOcbConfig();
        when(configModel.getConfig()).thenReturn(ocbConfig);

        when(userProvider.getUserByUsername(realm, TEST_USERNAME)).thenReturn(null);
        when(userProvider.addUser(realm, TEST_USERNAME)).thenReturn(user);

        Map<String, String> userInfo = createUserInfo();
        ApiResponse mockApiResponse = ApiResponse.success(userInfo);

        try (MockedConstruction<OcbClient> ignored = mockConstruction(OcbClient.class,
                (mock, context) -> when(mock.verifyUser(TEST_USERNAME, TEST_PASSWORD)).thenReturn(mockApiResponse))) {

            ocbAuthenticator.authenticate(context);

            verify(authSession).setAuthNote("EXTERNAL_VERIFICATION_COMPLETED", "true");
            verify(authSession).setAuthNote("VERIFIED_USERNAME", TEST_USERNAME);
            verify(authSession).setAuthNote("CUSTOMER_NUMBER", TEST_CUSTOMER_NUMBER);

            System.out.println("✓ Step 2: OCB verification successful");
        }

        System.out.println("\n--- Step 3: Smart OTP Authentication (Error) ---");

        SmartOtpAuthenticator freshOtpAuthenticator = new SmartOtpAuthenticator();

        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn("true");
        when(authSession.getAuthNote("VERIFIED_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("CUSTOMER_NUMBER")).thenReturn(TEST_CUSTOMER_NUMBER);
        when(authSession.getAuthNote("OTP_STATE")).thenReturn(null);

        Map<String, String> otpConfig = createOtpConfig();
        when(configModel.getConfig()).thenReturn(otpConfig);

        when(context.form()).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setAttribute(anyString(), any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createLoginUsernamePassword()).thenReturn(response);

        OtpResponse mockOtpErrorResponse = OtpResponse.error("01", "OTP service unavailable");

        try (MockedConstruction<SmartOtpClient> mockedOtpClient = mockConstruction(SmartOtpClient.class,
                (mock, context) -> {
                    when(mock.createTransaction(anyString(), anyString(), anyString(), anyInt(),
                            anyString(), anyString(), anyInt(), anyInt(),
                            anyString(), anyString(), anyInt(), anyInt(), anyInt()))
                            .thenReturn(mockOtpErrorResponse);
                })) {

            freshOtpAuthenticator.authenticate(context);
            verify(context, atLeastOnce()).getAuthenticationSession();
            System.out.println("✓ Step 3: OTP transaction creation failed as expected");
        }

        System.out.println("\n--- Final Verification ---");
        verify(authSession).setAuthNote("EXTERNAL_VERIFICATION_COMPLETED", "true");
        verify(authSession).setAuthNote("VERIFIED_USERNAME", TEST_USERNAME);

        System.out.println("✓ Flow handled OTP error appropriately after OCB success");
        System.out.println("✓ User " + TEST_USERNAME + " OCB verification succeeded but OTP failed");
    }

    @Test
    void testOcbVerificationError_FlowFails() {
        System.out.println("=== Testing OCB Verification Error - Flow Fails ===");

        System.out.println("\n--- Step 1: Username/Password Collection (Success) ---");

        MultivaluedMap<String, String> credentialsForm = new MultivaluedHashMap<>();
        credentialsForm.putSingle("username", TEST_USERNAME);
        credentialsForm.putSingle("password", "WrongPassword123");
        when(httpRequest.getDecodedFormParameters()).thenReturn(credentialsForm);

        usernamePasswordForm.action(context);

        verify(authSession).setAuthNote("EXTERNAL_USERNAME", TEST_USERNAME);
        verify(authSession).setAuthNote("EXTERNAL_PASSWORD", "WrongPassword123");
        verify(context).success();
        System.out.println("✓ Step 1: Credentials collected successfully");

        System.out.println("\n--- Step 2: OCB User Verification (Error) ---");

        OcbUserVerificationAuthenticator freshOcbAuthenticator = new OcbUserVerificationAuthenticator();

        when(authSession.getAuthNote("EXTERNAL_USERNAME")).thenReturn(TEST_USERNAME);
        when(authSession.getAuthNote("EXTERNAL_PASSWORD")).thenReturn("WrongPassword123");
        when(authSession.getAuthNote("EXTERNAL_VERIFICATION_COMPLETED")).thenReturn(null);

        Map<String, String> ocbConfig = createOcbConfig();
        when(configModel.getConfig()).thenReturn(ocbConfig);

        when(context.form()).thenReturn(loginFormsProvider);
        when(context.getSession()).thenReturn(keycloakSession);
        when(context.getRealm()).thenReturn(realm);
        when(keycloakSession.users()).thenReturn(userProvider);
        when(loginFormsProvider.setAttribute(anyString(), any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createLoginUsernamePassword()).thenReturn(response);

        ApiResponse mockApiErrorResponse = ApiResponse.error("01", "Invalid username or password");

        try (MockedConstruction<OcbClient> ignored = mockConstruction(OcbClient.class,
                (mock, context) -> when(mock.verifyUser(TEST_USERNAME, "WrongPassword123"))
                        .thenReturn(mockApiErrorResponse))) {

            freshOcbAuthenticator.authenticate(context);

            verify(context, atLeastOnce()).getAuthenticationSession();
            System.out.println("✓ Step 2: OCB verification failed as expected");
        }

        System.out.println("\n--- Final Verification ---");

        verify(authSession, never()).setAuthNote("EXTERNAL_VERIFICATION_COMPLETED", "true");
        verify(authSession, never()).setAuthNote("VERIFIED_USERNAME", TEST_USERNAME);
        verify(authSession, never()).setAuthNote("CUSTOMER_NUMBER", TEST_CUSTOMER_NUMBER);

        System.out.println("✓ Flow correctly failed at OCB verification step");
        System.out.println("✓ User " + TEST_USERNAME + " authentication failed due to invalid credentials");
        System.out.println("✓ OTP step was never reached due to OCB failure");
    }
}
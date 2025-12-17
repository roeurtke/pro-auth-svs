package com.core.auth.constants;

public class ApiPaths {
    public static final String API_V1 = "/api/v1";
    public static final String AUTH = API_V1 + "/auth";
    public static final String USERS = API_V1 + "/users";
    public static final String ADMIN = API_V1 + "/admin";
    public static final String ROLES = API_V1 + "/roles";
    public static final String PERMISSIONS = API_V1 + "/permissions";
    
    // Auth endpoints
    public static final String LOGIN = "/login";
    public static final String REGISTER = "/register";
    public static final String REFRESH = "/refresh";
    public static final String LOGOUT = "/logout";
    public static final String VERIFY = "/verify";
    public static final String MFA_SETUP = "/mfa/setup";
    public static final String MFA_VERIFY = "/mfa/verify";
    public static final String MFA_DISABLE = "/mfa/disable";
    public static final String PASSWORD_RESET_REQUEST = "/password/reset/request";
    public static final String PASSWORD_RESET_CONFIRM = "/password/reset/confirm";
    
    // User endpoints
    public static final String ME = "/me";
    public static final String UPDATE_PROFILE = "/profile";
    public static final String CHANGE_PASSWORD = "/password/change";
}
package com.mindpool.security.service;

import java.security.Principal;

import javax.security.auth.login.LoginException;

public interface UserAuthenticationService {

	public static final String UNKNOWN_USER_ERROR = "UNKNOWN_USER_ERROR";
	public static final String USER_DISABLED_ERROR = "USER_DISABLED_ERROR";
	public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";
	public static final String PASSWORD_EXPIRED = "PASSWORD_EXPIRED";
	public static final String BAD_PASSWORD = "BAD_PASSWORD";
	
	public Principal authenticate(String username, String password);
	public String getReason();
	
}

package com.mindpool.security.exceptions;

import javax.security.auth.login.LoginException;

public class PasswordExpiredException extends LoginException {

	private static final long serialVersionUID = 1L;
	
	public PasswordExpiredException(String message) {
		super(message);
	}
}

package com.mindpool.security.exceptions;

import javax.security.auth.login.LoginException;

public class UserDisabledException extends LoginException {

	private static final long serialVersionUID = 1L;
	
	public UserDisabledException(String message) {
		super(message);
	}
}

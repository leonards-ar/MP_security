package com.mindpool.security.exceptions;

import javax.security.auth.login.LoginException;

public class PasswordChangeRequiredException extends LoginException {
	
	private static final long serialVersionUID = 1L;
	
	public PasswordChangeRequiredException(String message) {
		super(message);
	}

}

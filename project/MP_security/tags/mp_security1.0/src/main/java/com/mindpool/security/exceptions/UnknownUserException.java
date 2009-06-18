package com.mindpool.security.exceptions;

import javax.security.auth.login.LoginException;

public class UnknownUserException extends LoginException {

	private static final long serialVersionUID = 1L;
	
	public UnknownUserException(String message) {
		super(message);
	}
}

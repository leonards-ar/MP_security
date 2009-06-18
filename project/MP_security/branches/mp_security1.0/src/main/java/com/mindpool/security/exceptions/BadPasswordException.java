package com.mindpool.security.exceptions;

import javax.security.auth.login.LoginException;


public class BadPasswordException extends LoginException {
	private static final long serialVersionUID = 1L;
	
	public BadPasswordException(String message) {
		super(message);
	}

}

package com.mindpool.security.auth.CallbackHandler;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class UserPasswordCallBackHandler implements CallbackHandler {

	private String username;
	private String password;

	public UserPasswordCallBackHandler(String username, String password) {
		super();
		this.username = username;
		this.password = password;
	}
	
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof NameCallback) {
				((NameCallback) callbacks[i]).setName(username);
			} else if (callbacks[i] instanceof PasswordCallback) {
				((PasswordCallback) callbacks[i]).setPassword(password
						.toCharArray());
			} else {
				throw new UnsupportedCallbackException(callbacks[i], "is not supported");
			}
		}
	}

}

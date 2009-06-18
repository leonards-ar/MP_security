package com.mindpool.security.auth.impl;

import java.security.Principal;

import javax.security.auth.login.LoginException;

import com.mindpool.security.principal.MockUser;
import com.mindpool.security.service.UserAuthenticationService;

public class UserAuthenticatorTestImpl implements UserAuthenticationService {

	MockUser user;
	
	
	public Principal authenticate(String username, String password) {
		if(username.equals(user.getUsername()) && password.equals(password)) {
			return user;
		}
		
		return null;
	}
	
	
	public void setUser(MockUser user){
		this.user = user;
	}
	
	public String getReason() {
		/* not implemented for this test */
		return null;
	}
	

}

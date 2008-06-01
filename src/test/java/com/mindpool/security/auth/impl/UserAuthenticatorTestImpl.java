package com.mindpool.security.auth.impl;

import java.util.Set;

import com.mindpool.security.principal.MockUser;
import com.mindpool.security.principal.SecurityUser;
import com.mindpool.security.service.UserAuthenticationService;

public class UserAuthenticatorTestImpl implements UserAuthenticationService {

	MockUser user;
	
	
	public SecurityUser authenticateUser(String username, String password) throws Exception {
		if(username.equals(user.getUsername()) && password.equals(password)) {
			return user;
		}
		
		return null;
	}
	
	public Set<String> getRoles(SecurityUser user) {
		return user.getRoles();
	}
	
	public Set<String> getPermissions(SecurityUser user) {
		throw new SecurityException("Method not implemented");
	}
	
	
	public void setUser(MockUser user){
		this.user = user;
	}
	

}

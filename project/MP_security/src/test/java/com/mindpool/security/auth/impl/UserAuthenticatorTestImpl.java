package com.mindpool.security.auth.impl;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import com.mindpool.security.auth.UserAuthenticationService;
import com.mindpool.security.principal.UserPrincipal;

public class UserAuthenticatorTestImpl implements UserAuthenticationService {

	private String username;
	private String password;
	
	private HashSet<String>roles = new HashSet<String>();
	
	
	public Principal authenticateUser(String username, String password) throws Exception {
		if(this.username.equals(username) && this.password.equals(password)) {
			return new UserPrincipal(username);
		}
		
		return null;
	}
	
	public Set<String> getRoles(Principal user) {
		
		return this.roles;
		
	}
	
	public void setUsername(String username){
		this.username = username;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public void setRoles(ArrayList<String> roles ){
		this.roles = new HashSet<String>(roles);
	}
	

}

package com.mindpool.security.service;

import java.util.Set;

import com.mindpool.security.principal.SecurityUser;

public interface UserAuthenticationService {

	public SecurityUser authenticateUser(String username, String password) throws Exception;
	
	public Set<String>getRoles(SecurityUser user);
	
	public Set<String>getPermissions(SecurityUser user);
		
}

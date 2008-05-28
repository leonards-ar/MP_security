package com.mindpool.security.auth;

import java.security.Principal;
import java.util.Set;

public interface UserAuthenticationService {

	public Principal authenticateUser(String username, String password) throws Exception;
	
	public Set<String>getRoles(Principal username);
		
}

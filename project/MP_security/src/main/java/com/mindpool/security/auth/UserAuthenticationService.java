package com.mindpool.security.auth;

import java.security.Principal;
import java.util.Set;

public interface UserAuthenticationService {

	public Set<String> authenticateUser(String username, String password) throws Exception;
		
}

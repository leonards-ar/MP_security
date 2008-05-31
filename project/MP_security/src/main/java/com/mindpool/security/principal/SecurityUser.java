package com.mindpool.security.principal;

import java.security.Principal;
import java.util.Set;

public interface SecurityUser extends Principal{

	public Set<String>getPermissions();
	
	public Set<String>getRoles();
	
}

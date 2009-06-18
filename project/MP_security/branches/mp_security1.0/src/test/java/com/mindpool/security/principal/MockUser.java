package com.mindpool.security.principal;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

public class MockUser implements Principal {

	private String username;
	private String password;
	
	private Set<String>roles = new HashSet<String>();
	
	public Set<String> getPermissions() {
		return null;
	}

	public Set<String> getRoles() {
		return roles;
	}

	public String getName() {
		return username;
	}
	
	public String getUsername() {
		return username;
	}
	
	public void setUsername(String username){
		this.username = username;
	}
	
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	public void setRoles(Set<String> roles ){
		this.roles = roles;
	}

}

package com.mindpool.security.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.Set;

import javax.naming.NamingException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import junit.framework.TestCase;

import com.mindpool.security.auth.CallbackHandler.UserPasswordCallBackHandler;

public class ApplicationLoginModuleTest extends TestCase {

	public ApplicationLoginModuleTest(String name) {
		super(name);
	}
	
	public void setUp() throws IOException, NamingException{
		String osWork = System.getProperty("user.dir");
		System.setProperty("java.security.auth.login.config", osWork + "\\src\\test\\resources\\spm_jaas.conf");
		
	}
	
	public void testLogin() {
		LoginContext lc = null;
		try {
		    lc = new LoginContext("spm", new UserPasswordCallBackHandler("torimpo", "123"));
		    lc.login();
		    Set<Principal> principals = lc.getSubject().getPrincipals();
		  //I will take only two principals (The username and the name of the group		    
		    assertEquals(principals.size(), 2);

		    for(Principal principal: principals) {
		    	System.out.println(principal.getName());
		    }
		    
		    
		} catch (LoginException le) {
		    System.err.println("Cannot create LoginContext. "
		        + le.getMessage());
		    System.exit(-1);
		} catch (SecurityException se) {
		    System.err.println("Cannot create LoginContext. "
		        + se.getMessage());
		    System.exit(-1);
		} 
	}
}

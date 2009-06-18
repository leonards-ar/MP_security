package com.mindpool.security.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Set;

import javax.naming.NamingException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import junit.framework.TestCase;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.mindpool.security.auth.CallbackHandler.UserPasswordCallBackHandler;

public class ApplicationLoginModuleTest extends TestCase {

	public ApplicationLoginModuleTest(String name) {
		super(name);
	}
	
	public void setUp() throws IOException, NamingException{
		String osWork = System.getProperty("user.dir");
		System.setProperty("java.security.auth.login.config", osWork + "/src/test/resources/spm_jaas.conf");
		
	}
	
	public void testLogin() {
		LoginContext lc = null;
		try {
		    lc = new LoginContext("spm", new UserPasswordCallBackHandler("torimpo", "java1234"));
		    lc.login();
		    Set<Principal> principals = lc.getSubject().getPrincipals();
		  //I will take only two principals (The username and the name of the group		    
		    assertEquals(principals.size(), 1);

		    for(Principal principal: principals) {
		    	System.out.println(principal.getName());
		    }
		    
		    
		} catch (LoginException le) {
		    System.err.println("Cannot create LoginContext. "
		        + le.getMessage());
		    le.printStackTrace();
		    System.exit(-1);
		} catch (SecurityException se) {
		    System.err.println("Cannot create LoginContext. "
		        + se.getMessage());
		    se.printStackTrace();
		    System.exit(-1);
		} 
	}
}

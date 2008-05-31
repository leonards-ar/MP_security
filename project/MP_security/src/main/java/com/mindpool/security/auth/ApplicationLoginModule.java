package com.mindpool.security.auth;

import java.security.acl.Group;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.xml.XmlBeanFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.mindpool.security.principal.SecurityUser;
import com.mindpool.security.principal.UserGroup;
import com.mindpool.security.principal.UserPrincipal;
import com.mindpool.security.service.UserAuthenticationService;

public class ApplicationLoginModule implements LoginModule {

	private static final Logger log = Logger
			.getLogger(ApplicationLoginModule.class);

	// initial state
	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map sharedState;
	private Map options;

	
	private static final String GROUP_NAME = "GROUP_NAME";
	private static final String PERMISSION_NAME = "PERMISSION_NAME";
	private static final String DEFAULT_GROUP_NAME = "Roles";
	private static final String DEFAULT_PERMISSION_NAME = "Permissions";
	private static final String USE_PERMISSIONS_NAME = "USE_PERMISSIONS";
	private static final String APP_CONTEXT_LOCATION = "APP_CONTEXT_LOCATION";
	private static final String USER_AUTH_BEAN_NAME = "USER_AUTH_BEAN_NAME";

	private String groupName = null;
	private String permissionName = null;

	private Resource contextLocation = null;
	private String userBeanName = null;

	private boolean debug = false;
	private boolean hasPermissions = false;
	
	private boolean succeeded = false;
	private boolean commitSucceeded = false;

	private SecurityUser user;
	private Set<String> roles;
	private Set<String> permissions;

	/**
	 * <p>
	 * This method is called if the LoginContext's overall authentication
	 * failed. (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
	 * LoginModules did not succeed).
	 * 
	 * <p>
	 * If this LoginModule's own authentication attempt succeeded (checked by
	 * retrieving the private state saved by the <code>login</code> and
	 * <code>commit</code> methods), then this method cleans up any state that
	 * was originally saved.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the abort fails.
	 * 
	 * @return false if this LoginModule's own login and/or commit attempts
	 *         failed, and true otherwise.
	 */
	public boolean abort() throws LoginException {
		if (succeeded == false) {
			return false;
		} else if (succeeded == true && commitSucceeded == false) {
			// login succeeded but overall authentication failed
			succeeded = false;
		} else {
			// overall authentication succeeded and commit succeeded,
			// but someone else's commit failed
			logout();
		}
		return true;
	}

	/**
	 * <p>
	 * This method is called if the LoginContext's overall authentication
	 * succeeded (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
	 * LoginModules succeeded).
	 * 
	 * <p>
	 * If this LoginModule's own authentication attempt succeeded (checked by
	 * retrieving the private state saved by the <code>login</code> method),
	 * then this method associates a <code>SamplePrincipal</code> with the
	 * <code>Subject</code> located in the <code>LoginModule</code>. If
	 * this LoginModule's own authentication attempted failed, then this method
	 * removes any state that was originally saved.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the commit fails.
	 * 
	 * @return true if this LoginModule's own login and commit attempts
	 *         succeeded, or false otherwise.
	 */
	public boolean commit() throws LoginException {
		if (succeeded == false) {
			return false;
		}

		if (!subject.getPrincipals().contains(user)) {
			subject.getPrincipals().add(user);
			Group group = new UserGroup(groupName);
			for (String role : roles) {
				group.addMember(new UserPrincipal(role));
			}
			subject.getPrincipals().add(group);
		}

		if (debug) {
			log.debug("added SamplePrincipal to Subject");
		}

		commitSucceeded = true;

		return true;
	}

	/**
	 * Initialize this <code>LoginModule</code>.
	 * 
	 * <p>
	 * 
	 * @param subject
	 *            the <code>Subject</code> to be authenticated.
	 *            <p>
	 * 
	 * @param callbackHandler
	 *            a <code>CallbackHandler</code> for communicating with the
	 *            end user (prompting for user names and passwords, for
	 *            example).
	 *            <p>
	 * 
	 * @param sharedState
	 *            shared <code>LoginModule</code> state.
	 *            <p>
	 * 
	 * @param options
	 *            options specified in the login <code>Configuration</code>
	 *            for this particular <code>LoginModule</code>.
	 */
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		// initialize any configured options
		debug = "true".equalsIgnoreCase((String) options.get("debug"));
		groupName = (options.get(GROUP_NAME) != null) ? (String) options
				.get(GROUP_NAME) : DEFAULT_GROUP_NAME;
				
		hasPermissions = "true".equalsIgnoreCase((String) options.get(USE_PERMISSIONS_NAME));
		if(hasPermissions) {
			permissionName = (options.get(PERMISSION_NAME) != null) ? (String) options
					.get(PERMISSION_NAME) : DEFAULT_PERMISSION_NAME;
		}
		
	    contextLocation = new ClassPathResource((String)options.get(APP_CONTEXT_LOCATION));
	    userBeanName = (String) options.get(USER_AUTH_BEAN_NAME);
	    
	    if (debug){
	    	log.debug("contextLocation: " + contextLocation);
	    	log.debug("userBeanName: " + userBeanName);
	    }

	}

	/**
	 * Authenticate the user by prompting for a user name and password.
	 * 
	 * <p>
	 * 
	 * @return true in all cases since this <code>LoginModule</code> should
	 *         not be ignored.
	 * 
	 * @exception FailedLoginException
	 *                if the authentication fails.
	 *                <p>
	 * 
	 * @exception LoginException
	 *                if this <code>LoginModule</code> is unable to perform
	 *                the authentication.
	 */
	public boolean login() throws LoginException {
		if (contextLocation == null || userBeanName == null) {
			throw new LoginException("One or many parameters are missing");
		}
		try {
			BeanFactory bf = new XmlBeanFactory(contextLocation);

			UserAuthenticationService userAuthenticator = (UserAuthenticationService) bf
					.getBean(userBeanName);

			String username;
			char[] password;

			Callback[] callbacks = new Callback[2];
			callbacks[0] = new NameCallback("user name: ");
			callbacks[1] = new PasswordCallback("password: ", false);

			callbackHandler.handle(callbacks);
			username = ((NameCallback) callbacks[0]).getName();
			char[] tmpPassword = ((PasswordCallback) callbacks[1])
					.getPassword();
			if (tmpPassword == null) {
				// treat a NULL password as an empty password
				tmpPassword = new char[0];
			}
			password = new char[tmpPassword.length];
			System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
			((PasswordCallback) callbacks[1]).clearPassword();

			// print debugging information
			if (debug) {
				log.debug("user entered user name: " + username);
				log.debug("user entered password: " + String.valueOf(password));
			}

			user = userAuthenticator.authenticateUser(username, String.valueOf(tmpPassword));

			
			if (user == null) {
				// authentication failed -- clean out state
				if (debug)
					log.debug("authentication failed");
				
				succeeded = false;
				username = null;
				for (int i = 0; i < password.length; i++)
					password[i] = ' ';
				throw new FailedLoginException("User not found.");
			}
			roles = userAuthenticator.getRoles(user);
			
			if(hasPermissions){
				permissions = userAuthenticator.getPermissions(user);
			}
			
			if (debug)
				log.debug("authentication succeeded");
			
			succeeded = true;
			
		} catch (java.io.IOException ioe) {
			throw new LoginException(ioe.toString());
		} catch (UnsupportedCallbackException uce) {
			throw new LoginException("Error: " + uce.getCallback().toString()
					+ " not available to garner authentication information "
					+ "from the user");
		} catch (Exception e) {
			throw new LoginException("Unexpected Exception: " + e.getMessage());
		}
		return succeeded;
	}

	/**
	 * Logout the user.
	 * 
	 * <p>
	 * This method removes the <code>SamplePrincipal</code> that was added by
	 * the <code>commit</code> method.
	 * 
	 * <p>
	 * 
	 * @exception LoginException
	 *                if the logout fails.
	 * 
	 * @return true in all cases since this <code>LoginModule</code> should
	 *         not be ignored.
	 */
	public boolean logout() throws LoginException {
		subject.getPrincipals().remove(user);
		succeeded = false;
		succeeded = commitSucceeded;

		user = null;
		return true;
	}

}

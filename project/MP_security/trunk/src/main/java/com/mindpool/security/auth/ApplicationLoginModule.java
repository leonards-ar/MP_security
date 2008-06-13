package com.mindpool.security.auth;

import java.security.Principal;
import java.util.Map;

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
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import com.mindpool.security.exceptions.BadPasswordException;
import com.mindpool.security.exceptions.PasswordChangeRequiredException;
import com.mindpool.security.exceptions.PasswordExpiredException;
import com.mindpool.security.exceptions.UserDisabledException;
import com.mindpool.security.service.UserAuthenticationService;

public class ApplicationLoginModule implements LoginModule {

	private static final Logger log = Logger.getLogger(ApplicationLoginModule.class);

	// initial state
	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map sharedState;
	private Map options;

	
	private static final String APP_CONTEXT_LOCATION = "APP_CONTEXT_LOCATION";
	private static final String USER_AUTH_BEAN_NAME = "USER_AUTH_BEAN_NAME";


	private String contextLocation = null;
	private String userBeanName = null;

	private boolean succeeded = false;
	private boolean commitSucceeded = false;

	private Principal user;
	
	private String username;
	private char[] password;

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
		}

		if (log.isDebugEnabled()) {
			log.debug("added user to Subject");
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
			
	    contextLocation = contextLocation = (String)options.get(APP_CONTEXT_LOCATION);
	    userBeanName = (String) options.get(USER_AUTH_BEAN_NAME);
	    
	    if (log.isDebugEnabled()){
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
		ApplicationContext ctx = new ClassPathXmlApplicationContext(contextLocation);
		UserAuthenticationService userAuthenticator = (UserAuthenticationService) ctx.getBean(userBeanName);
		try {

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
			if (log.isDebugEnabled()) {
				log.debug("user entered user name: " + username);
				log.debug("user entered password: " + String.valueOf(password));
			}
			
			user = userAuthenticator.authenticate(username, String.valueOf(tmpPassword));
		} catch (java.io.IOException ioe) {
					throw new LoginException(ioe.toString());
				} catch (UnsupportedCallbackException uce) {
					throw new LoginException("Error: " + uce.getCallback().toString()
							+ " not available to garner authentication information "
							+ "from the user");
				}
			
			
			if (user == null) {
				// authentication failed -- clean out state
				if (log.isDebugEnabled())
					log.debug("authentication failed");
				
				succeeded = false;
				username = null;
				for (int i = 0; i < password.length; i++)
					password[i] = ' ';
				String reason = userAuthenticator.getReason();
				if(UserAuthenticationService.UNKNOWN_USER_ERROR.equals(reason)) {
					throw new FailedLoginException("User not found");
				} else if(UserAuthenticationService.PASSWORD_CHANGE_REQUIRED.equals(reason)) {
					throw new PasswordChangeRequiredException("You need to change your password");
				} else if(UserAuthenticationService.PASSWORD_EXPIRED.equals(reason)) {
					throw new PasswordExpiredException("Your password has expired"); 
				} else if(UserAuthenticationService.USER_DISABLED_ERROR.equals(reason)) {
					throw new UserDisabledException("Your user has expired");
				} else if (UserAuthenticationService.BAD_PASSWORD.equals(reason)) {
					throw new BadPasswordException("Wrong password");
				}
			}
			
			if (log.isDebugEnabled())
				log.debug("authentication succeeded");
			
			succeeded = true;
			
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

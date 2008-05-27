package com.mindpool.security.principal;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class UserGroup implements Group {

	private final String name;
	private final Set<Principal> users = new HashSet<Principal>();

	public UserGroup(String name) {
		this.name = name;
	}
	
	public boolean addMember(Principal user) {
		return users.add(user);
	}

	public boolean removeMember(Principal user) {
		return users.remove(user);
	}

	public boolean isMember(Principal member) {
		return users.contains(member);
	}

	public Enumeration<? extends Principal> members() {
		return Collections.enumeration(users);
	}

	public String getName() {
		return name;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final UserGroup other = (UserGroup) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		return true;

	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

}

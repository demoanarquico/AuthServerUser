package cl.bci.auth.security.config.entity;

import java.io.Serializable;

public class AuthorityPK implements Serializable  {

	private String username;
	
	private String authority;
	

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

	@Override
	public String toString() {
		return "AuthorityPK [username=" + username + ", authority=" + authority + "]";
	}
	
	

	
}
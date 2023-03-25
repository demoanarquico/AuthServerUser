package cl.bci.auth.security.config.entity;


import java.util.Arrays;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "oauth_refresh_token")
public class RefreshTokenEntity {
	
	@Id
	@Column(name = "token_id" )
	private String tokenId;

	@Column(name = "token" )
	private byte[] token;
	
	@Column(name = "authentication" )
	private byte[] authentication;

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public byte[] getToken() {
		return token;
	}

	public void setToken(byte[] token) {
		this.token = token;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public void setAuthentication(byte[] authentication) {
		this.authentication = authentication;
	}

	@Override
	public String toString() {
		return "OauthRefreshTokenEntity [tokenId=" + tokenId + ", token=" + Arrays.toString(token) + ", authentication="
				+ Arrays.toString(authentication) + "]";
	}
	
}
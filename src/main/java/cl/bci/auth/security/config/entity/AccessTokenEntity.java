package cl.bci.auth.security.config.entity;


import java.util.Arrays;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

@Entity
@Table(name = "oauth_access_token")
public class AccessTokenEntity {
	
	@Id
	@Column(name = "authentication_id" )
	private String authenticationId;
	
	@Column(name = "token_id" )
	private String tokenId;
	
	@Column(name = "token" )
	private byte[] token;
	
	@Column(name = "user_name" )
	private String userName;
	
	@Column(name = "client_id" )
	private String clientId;
	
	@Lob
	@Column(name = "authentication", length = 1000 )
	private byte[] authentication;
	
	@Column(name = "refresh_token" )
	private String refreshToken;

	public String getAuthenticationId() {
		return authenticationId;
	}

	public void setAuthenticationId(String authenticationId) {
		this.authenticationId = authenticationId;
	}

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

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public void setAuthentication(byte[] authentication) {
		this.authentication = authentication;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	@Override
	public String toString() {
		return "OauthAccessTokenEntity [authenticationId=" + authenticationId + ", tokenId=" + tokenId + ", token="
				+ Arrays.toString(token) + ", userName=" + userName + ", clientId=" + clientId + ", authentication="
				+ Arrays.toString(authentication) + ", refreshToken=" + refreshToken + "]";
	}


}
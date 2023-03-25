package cl.bci.auth.security.config;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.transaction.annotation.Transactional;

import cl.bci.auth.security.config.entity.AccessTokenEntity;
import cl.bci.auth.security.config.entity.RefreshTokenEntity;
import cl.bci.auth.security.config.repository.AccessTokenRepository;
import cl.bci.auth.security.config.repository.AuthorityRepository;
import cl.bci.auth.security.config.repository.RefreshTokenRepository;

/**
 * Implementation of token services that stores tokens in a database.
 *
 */
public class JpaTokenStore implements TokenStore {

	private static final Log logger = LogFactory.getLog(JpaTokenStore.class);

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	@Autowired
	private AccessTokenRepository accessTokenRepository;
	
	@Autowired
	private RefreshTokenRepository refreshTokenRepository;
	
	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		OAuth2AccessToken accessToken = null;

		String key = authenticationKeyGenerator.extractKey(authentication);
		
		AccessTokenEntity entAccessToken = accessTokenRepository.findByAuthenticationId( key );

		try {
			
			if ( entAccessToken != null ) {
				
				accessToken = deserializeAccessToken( entAccessToken.getToken() );
				
//				if (accessToken != null
//						&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
//					removeAccessToken(accessToken.getValue());
//					// Keep the store consistent (maybe the same user is represented by this authentication but the details have
//					// changed)
//					storeAccessToken(accessToken, authentication);
//				}
				
			}

		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Failed to find access token for authentication " + authentication);
			}
		}
		catch (IllegalArgumentException e) {
			logger.error("Could not extract access token for authentication " + authentication, e);
		}

		return accessToken;
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		String refreshToken = null;
		if (token.getRefreshToken() != null) {
			refreshToken = token.getRefreshToken().getValue();
		}
		
		AccessTokenEntity entAccessToken = accessTokenRepository.findByTokenId(extractTokenKey( token.getValue() ) );
		
		
		if (entAccessToken == null) {
			entAccessToken = new AccessTokenEntity ();
		}

		entAccessToken.setTokenId( extractTokenKey(token.getValue()) );
		entAccessToken.setToken( serializeAccessToken(token) );
		entAccessToken.setAuthenticationId( authenticationKeyGenerator.extractKey(authentication) );
		entAccessToken.setUserName(authentication.isClientOnly() ? null : authentication.getName() );
		entAccessToken.setClientId(authentication.getOAuth2Request().getClientId() );
		entAccessToken.setAuthentication( serializeAuthentication( authentication) );
		entAccessToken.setRefreshToken( extractTokenKey(refreshToken) );
				
		accessTokenRepository.saveAndFlush( entAccessToken );

	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		OAuth2AccessToken accessToken = null;

		try {

			AccessTokenEntity entAccessToken = accessTokenRepository.findByTokenId( extractTokenKey(tokenValue) );
			
			if (entAccessToken != null) {
				accessToken = deserializeAccessToken( entAccessToken.getToken() );
			}


		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled()) {
				logger.info("Failed to find access token for token " + tokenValue);
			}
		}
		catch (IllegalArgumentException e) {
			logger.warn("Failed to deserialize access token for " + tokenValue, e);
			removeAccessToken(tokenValue);
		}

		return accessToken;
	}

	public void removeAccessToken(OAuth2AccessToken token) {
		removeAccessToken(token.getValue());
	}

	public void removeAccessToken(String tokenValue) {
		accessTokenRepository.deleteBytokenId(extractTokenKey(tokenValue)  );
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}
	

	public OAuth2Authentication readAuthentication(String token) {
		OAuth2Authentication authentication = null;

		try {

			AccessTokenEntity entAccessToken = accessTokenRepository.findByTokenId( extractTokenKey(token) );

			if (entAccessToken != null) {
				authentication =  deserializeAuthentication( entAccessToken.getAuthentication() );
			}


		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled()) {
				logger.info("Failed to find access token for token " + token);
			}
		}
		catch (IllegalArgumentException e) {
			logger.warn("Failed to deserialize authentication for " + token, e);
			removeAccessToken(token);
		}

		return authentication;
	}

	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		
		RefreshTokenEntity entRefreshToken = refreshTokenRepository.findBytokenId( extractTokenKey(refreshToken.getValue()) );
		
	
		if (entRefreshToken == null) {
			entRefreshToken = new RefreshTokenEntity ();
		}

		entRefreshToken.setTokenId( extractTokenKey(refreshToken.getValue()) );
		entRefreshToken.setToken( serializeRefreshToken(refreshToken) );
		entRefreshToken.setAuthentication( serializeAuthentication(authentication));
		refreshTokenRepository.saveAndFlush( entRefreshToken );

	}

	public OAuth2RefreshToken readRefreshToken(String token) {
		OAuth2RefreshToken refreshToken = null;
		
		RefreshTokenEntity entRefreshToken = refreshTokenRepository.findBytokenId( extractTokenKey(token) );
		
		try {

			if (entRefreshToken != null) {
				refreshToken = deserializeRefreshToken( entRefreshToken.getToken() );
			}
	
		}catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled()) {
				logger.info("Failed to find refresh token for token " + token);
			}
		}
		catch (IllegalArgumentException e) {
			logger.warn("Failed to deserialize refresh token for token " + token, e);
			removeRefreshToken(token);
		}

		return refreshToken;
	}

	public void removeRefreshToken(OAuth2RefreshToken token) {

		removeRefreshToken(token.getValue());
	}

	public void removeRefreshToken(String token) {
		refreshTokenRepository.deleteById( extractTokenKey(token) );
		refreshTokenRepository.flush();
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
		OAuth2Authentication authentication = null;

			
			RefreshTokenEntity entRefreshToken = refreshTokenRepository.findBytokenId( extractTokenKey(value) );
			
			try {
				
				if (entRefreshToken != null) {
					authentication = deserializeAuthentication( entRefreshToken.getAuthentication() );
				}
			}catch (EmptyResultDataAccessException e) {
				if (logger.isInfoEnabled()) {
					logger.info("Failed to find access token for token " + value);
				}
			}
			catch (IllegalArgumentException e) {
				logger.warn("Failed to deserialize access token for " + value, e);
				removeRefreshToken(value);
			}

		return authentication;
	}

	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	public void removeAccessTokenUsingRefreshToken(String refreshToken) {
		accessTokenRepository.deleteByRefreshToken( extractTokenKey(refreshToken) );
		accessTokenRepository.flush();
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {

			AccessTokenEntity entAccessToken = accessTokenRepository.findByClientId( clientId );
			accessTokens.add( deserializeAccessToken( entAccessToken.getToken() ) );

		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled()) {
				logger.info("Failed to find access token for clientId " + clientId);
			}
		}

		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {

			 AccessTokenEntity entAccessToken = accessTokenRepository.findByUserName( userName );
			 
			 if (entAccessToken != null) {
				 accessTokens.add( deserializeAccessToken( entAccessToken.getToken() ) );
			 }

		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled())
				logger.info("Failed to find access token for userName " + userName);
		}
		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {
			
			 AccessTokenEntity entAccessToken = accessTokenRepository.findByUserNameAndClientId(userName, clientId);
			 
			 if (entAccessToken != null) {
				 accessTokens.add( deserializeAccessToken( entAccessToken.getToken() ) );
			 }
			 
		}
		catch (EmptyResultDataAccessException e) {
			if (logger.isInfoEnabled()) {
				logger.info("Failed to find access token for clientId " + clientId + " and userName " + userName);
			}
		}
		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	private List<OAuth2AccessToken> removeNulls(List<OAuth2AccessToken> accessTokens) {
		List<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AccessToken token : accessTokens) {
			if (token != null) {
				tokens.add(token);
			}
		}
		return tokens;
	}

	protected String extractTokenKey(String value) {
		if (value == null) {
			return null;
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
		}

		try {
			byte[] bytes = digest.digest(value.getBytes("UTF-8"));
			return String.format("%032x", new BigInteger(1, bytes));
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
		}
	}


	protected byte[] serializeAccessToken(OAuth2AccessToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
		return SerializationUtils.serialize(authentication);
	}

	protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
		return SerializationUtils.deserialize(authentication);
	}


}
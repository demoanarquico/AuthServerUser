package cl.bci.auth.security.config.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import cl.bci.auth.security.config.entity.AccessTokenEntity;

@Repository
public interface AccessTokenRepository extends JpaRepository<AccessTokenEntity, String> {
	
	AccessTokenEntity findByTokenId ( String tokenId);
	
	AccessTokenEntity findByAuthenticationId ( String authenticationId);
	
	AccessTokenEntity findByClientId ( String clientId);
	
	AccessTokenEntity findByUserName ( String userName);
	
	AccessTokenEntity findByUserNameAndClientId ( String userName, String clientId);
	
	void deleteBytokenId( String tokenId); 
	
	void deleteByRefreshToken( String refreshToken); 
	
	
}

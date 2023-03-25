package cl.bci.auth.security.config.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import cl.bci.auth.security.config.entity.RefreshTokenEntity;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {
	
	RefreshTokenEntity findBytokenId ( String tokenId);
	
	void deleteBytokenId ( String tokenId);
	
	
}

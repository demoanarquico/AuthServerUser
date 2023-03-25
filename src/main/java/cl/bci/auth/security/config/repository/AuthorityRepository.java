package cl.bci.auth.security.config.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import cl.bci.auth.security.config.entity.AuthorityEntity;
import cl.bci.auth.security.config.entity.AuthorityPK;

@Repository
public interface AuthorityRepository extends JpaRepository<AuthorityEntity, AuthorityPK> {
	
	AuthorityEntity findByUsername ( String username);

}

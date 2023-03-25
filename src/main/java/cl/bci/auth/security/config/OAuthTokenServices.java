package cl.bci.auth.security.config;

import java.util.Objects;
import org.slf4j.Logger;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

public class OAuthTokenServices extends DefaultTokenServices {
	
	private static Logger logger;
	
    @Override
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        OAuth2AccessToken token = super.getAccessToken(authentication);
        try {
            if (Objects.isNull(token) || token.isExpired()) {
                return super.createAccessToken(authentication);
            }
        } catch (DuplicateKeyException dke) {
        	logger.info("Se encontró una clave duplicada. Se procede a retornar la misma");
            token = super.getAccessToken(authentication);
            logger.info("Se retorna el token. {}", token);
            return token;
        } catch (Exception ex) {
        	logger.info(String.format("Excepción al crear el token de acceso %s", ex));
        }
        return token;
    }

}
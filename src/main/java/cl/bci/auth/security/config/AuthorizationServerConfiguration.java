package cl.bci.auth.security.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    
    @Value( "${token.validity}" )
	private int tokenValidity;
    
    @Autowired
    private UserDetailsService userDetailsService;

    private TokenStore tokenStore;

    public AuthorizationServerConfiguration(final DataSource dataSource, final PasswordEncoder passwordEncoder,
                                            final AuthenticationManager authenticationManager) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JpaTokenStore();
        }
        return tokenStore;
    }

//    @BeanDBC
//    public DefaultTokenServices tokenServices() {
//        OAuthTokenServices tokenService = new OAuthTokenServices();
//        tokenService.setTokenStore(tokenStore);
//        tokenService.setAccessTokenValiditySeconds(tokenValidity);
//        tokenService.setSupportRefreshToken(true);
//        return tokenService;
//    }
    
    @Bean
    public CustomDefaultTokenServices tokenServices() {

    	CustomDefaultTokenServices tokenService = new CustomDefaultTokenServices();
    	  
	      tokenService.setTokenStore(tokenStore);
	      tokenService.setAccessTokenValiditySeconds(tokenValidity);
	      tokenService.setSupportRefreshToken(true);
	      
        return tokenService;
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
//        	    .userDetailsService(userDetailsService)
                .tokenServices(tokenServices());
//                .exceptionTranslator(loggingExceptionTranslator());
    }
    
  
//    @Bean
//    public WebResponseExceptionTranslator<OAuth2Exception> loggingExceptionTranslator() {
//        return new DefaultWebResponseExceptionTranslator() {
//            @Override
//            public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
//                // This is the line that prints the stack trace to the log. You can customise this to format the trace etc if you like
//                e.printStackTrace();
//
//                // Carry on handling the exception
//                ResponseEntity<OAuth2Exception> responseEntity = super.translate(e);
//                HttpHeaders headers = new HttpHeaders();
//                headers.setAll(responseEntity.getHeaders().toSingleValueMap());
//                OAuth2Exception excBody = responseEntity.getBody();
//                return new ResponseEntity<>(excBody, headers, responseEntity.getStatusCode());
//            }
//        };
//    }
    
    
    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.passwordEncoder(passwordEncoder)
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
    

}

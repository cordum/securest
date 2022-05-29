package tacocloud;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration
        .OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client
        .InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client
        .RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client
        .RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    @Bean
//  Если будут объявлены другие бины с этим типом, то этот бин имеет приоритет над всеми
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain
    authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//      Sets up some default behavior for the OAuth 2 authorization server
//      and a default form login  page
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient =
                RegisteredClient.withId(UUID.randomUUID().toString())// A random, unique identifier
                        .clientId("taco-admin-client")// Analogous to a username, but instead of a user, it is a client. In this case, "taco-admin-client"
                        .clientSecret(passwordEncoder.encode("secret"))// Analogous to a password for the user
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)// The OAuth 2 grant types that this client will support
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)// In this case, we’re enabling authorization code
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)// and refresh token grants
                        // One or more registered URLs that the authorization server can
                        // redirect  to  after  authorization  has  been  granted
                        .redirectUri("http://127.0.0.1:9090/login/oauth2/code/taco-admin-client")
                        .scope("writeIngredients")// One or more OAuth 2 scopes that this client is allowed to ask for
                        .scope("deleteIngredients")
                        .scope(OidcScopes.OPENID)
                        // In  this  case,  we’re  requiring  explicit  user  consent  before  granting  the
                        // requested scope. Without this, the scope would be implicitly granted after the user logs in
                        .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                        .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return new ProviderSettings().issuer("http://authserver:9000");
    }
    //Finally, because our authorization server will be producing JWT tokens, the tokens
    //will need to include a signature created using a JSON Web Key (JWK)3 as the signi`ng key.
    //Therefore, we’ll need a few beans to produce a JWK
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
package com.nishanth.UserService.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
    // oidc- open id connect - industry standard STEPS involved for AUTHENTICATION AND AUTHORISATION FOR
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Create the Authorization Server Configurer
        OAuth2AuthorizationServerConfigurer authorizationServerConfigure = OAuth2AuthorizationServerConfigurer.authorizationServer();

        // redirect to the login page when not authenticated from the authorisation server endpoint
        http
                .securityMatcher(authorizationServerConfigure.getEndpointsMatcher()) // Match only authorization server endpoints (e.g., /oauth2/token, /.well-known/jwks, etc.)
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigure.getEndpointsMatcher())) // Disable CSRF protection on auth server endpoints
                .exceptionHandling((exceptions) -> exceptions // Handle unauthenticated HTML requests by redirecting to login
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                ))
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))// Accept JWT tokens for protected resources (resource server behavior)
                .with(authorizationServerConfigure, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults())	// Initialize `OidcConfigurer`
                );
        return http.build();
    }
//    /auth/login auth+login   /login

//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
//        http
//                .exceptionHandling((exceptions) -> exceptions
//                        .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/login"),
//                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
//                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
//        return http.build();
//    }

    @Bean
    @Order(2) // what I want to authorise and not want to authorise
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().permitAll()
//                .anyRequest().authenticated() for temporary
        ).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean  //User repository is client repository so no need
    public RegisteredClientRepository  registeredClientRepository(){
        RegisteredClient oldClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("productservice")
                .clientSecret(bCryptPasswordEncoder().encode("passwordofproductserviceclient"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // how will the client authorize authToken+refreshToken+clientCredentials
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)//
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("localhost:8080/login/oauth2/code/oidc-client")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .postLogoutRedirectUri("localhost:8080")//when user logout
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oldClient);
        // when more clients store in a db
    }

    public JWKSource<SecurityContext> jwkSource(){//creating json web key
    KeyPair keyPair = generateRsaKeys();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKeys(){
        KeyPair keyPair;// for generating the token
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e){
            throw new IllegalStateException(e);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

}
// SpringSecurity -> class for basic auth login[email+password]
// springConfig -> Oauth based configuration
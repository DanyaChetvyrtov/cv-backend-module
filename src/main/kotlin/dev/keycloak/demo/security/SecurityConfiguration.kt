package dev.keycloak.demo.security

import jakarta.servlet.DispatcherType
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.intercept.AuthorizationFilter
import org.springframework.security.web.savedrequest.NullRequestCache

@Configuration
@EnableConfigurationProperties(KeycloakProperties::class, BffProperties::class)
class SecurityConfiguration(private val keycloak: KeycloakProperties, private val bff: BffProperties) {
    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        val publicIssuer = keycloak.issuerUri.trimEnd('/')
        val internalIssuer = keycloak.internalBaseUri.trimEnd('/')
        val client = ClientRegistration.withRegistrationId("keycloak")
            .clientId(keycloak.clientId).clientSecret(keycloak.clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(bff.publicUrl.trimEnd('/') + "/api/auth/callback/keycloak")
            .scope("openid", "profile", "email")
            .issuerUri(publicIssuer)
            .authorizationUri(publicIssuer + "/protocol/openid-connect/auth")
            .tokenUri(internalIssuer + "/protocol/openid-connect/token")
            .userInfoUri(internalIssuer + "/protocol/openid-connect/userinfo")
            .jwkSetUri(internalIssuer + "/protocol/openid-connect/certs")
            .userNameAttributeName("sub")
            .providerConfigurationMetadata(mapOf("end_session_endpoint" to publicIssuer + "/protocol/openid-connect/logout"))
            .clientName("Keycloak BFF")
            .build()
        return InMemoryClientRegistrationRepository(client)
    }

    @Bean
    fun authorizedClientRepository(): OAuth2AuthorizedClientRepository = HttpSessionOAuth2AuthorizedClientRepository()

    @Bean
    fun authorizedClientManager(
        registrations: ClientRegistrationRepository,
        clients: OAuth2AuthorizedClientRepository,
    ): OAuth2AuthorizedClientManager = DefaultOAuth2AuthorizedClientManager(registrations, clients).apply {
        setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode().refreshToken().build())
    }

    @Bean
    fun securityFilterChain(
        http: HttpSecurity,
        registrations: ClientRegistrationRepository,
        clients: OAuth2AuthorizedClientRepository,
        manager: OAuth2AuthorizedClientManager,
    ): SecurityFilterChain {
        val publicUrl = bff.publicUrl.trimEnd('/') + "/"
        val logout = OidcClientInitiatedLogoutSuccessHandler(registrations).apply {
            setPostLogoutRedirectUri(publicUrl)
            setDefaultTargetUrl(publicUrl)
        }
        return http
            // Stateful HttpOnly cookie authentication. Default session CSRF protection stays enabled.
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) }
            .requestCache { it.requestCache(NullRequestCache()) }
            .authorizeHttpRequests {
                it.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                it.requestMatchers(HttpMethod.GET, "/api/public", "/api/health", "/api/auth/csrf", "/actuator/health").permitAll()
                it.requestMatchers(HttpMethod.GET, "/api/auth/login", "/api/auth/register", "/api/auth/authorize/keycloak", "/api/auth/callback/keycloak").permitAll()
                it.requestMatchers(HttpMethod.GET, "/api/me").authenticated()
                it.requestMatchers(HttpMethod.GET, "/api/user").hasRole("USER")
                it.requestMatchers(HttpMethod.GET, "/api/admin").hasRole("ADMIN")
                it.requestMatchers(HttpMethod.POST, "/api/vision/detect").hasRole("USER")
                it.requestMatchers(HttpMethod.POST, "/api/employees/identifications").hasRole("USER")
                it.requestMatchers(HttpMethod.GET, "/api/employees").hasRole("ADMIN")
                it.requestMatchers(HttpMethod.POST, "/api/employees").hasRole("ADMIN")
                it.requestMatchers(HttpMethod.DELETE, "/api/employees/*").hasRole("ADMIN")
                it.anyRequest().denyAll()
            }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ ->
                    response.status = 401
                    response.contentType = "application/json"
                    response.writer.write("{\"detail\":\"Sign in through the BFF.\"}")
                }
                it.accessDeniedHandler { _, response, _ ->
                    response.status = 403
                    response.contentType = "application/json"
                    response.writer.write("{\"detail\":\"Access denied or invalid CSRF token.\"}")
                }
            }
            .oauth2Login {
                it.loginPage(publicUrl)
                it.authorizedClientRepository(clients)
                it.authorizationEndpoint { endpoint ->
                    endpoint.authorizationRequestResolver(BffAuthorizationRequestResolver(registrations))
                }
                it.redirectionEndpoint { endpoint -> endpoint.baseUri("/api/auth/callback/*") }
                it.userInfoEndpoint { endpoint -> endpoint.oidcUserService(KeycloakOidcUserService(keycloak.apiClientId)) }
                it.defaultSuccessUrl(publicUrl, true)
                it.failureHandler { _, response, _ -> response.sendRedirect(publicUrl + "?auth=error") }
            }
            .logout {
                it.logoutUrl("/api/auth/logout").logoutSuccessHandler(logout)
                it.invalidateHttpSession(true).clearAuthentication(true).deleteCookies("BFFSESSION")
            }
            .addFilterBefore(SessionRefreshFilter(manager), AuthorizationFilter::class.java)
            .build()
    }
}

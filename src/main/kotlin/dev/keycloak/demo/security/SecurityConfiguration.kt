package dev.keycloak.demo.security

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import jakarta.servlet.DispatcherType

@Configuration
@EnableConfigurationProperties(KeycloakProperties::class)
class SecurityConfiguration(
    private val keycloak: KeycloakProperties,
) {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val jwtConverter = JwtAuthenticationConverter().apply {
            setJwtGrantedAuthoritiesConverter(KeycloakAuthoritiesConverter(keycloak.apiClientId))
        }

        return http
            // The API accepts Bearer tokens only, never cookies or HTTP sessions.
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests {
                it.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                it.requestMatchers(HttpMethod.GET, "/api/public", "/actuator/health").permitAll()
                it.requestMatchers(HttpMethod.GET, "/api/me").authenticated()
                it.requestMatchers(HttpMethod.GET, "/api/user").hasRole("USER")
                it.requestMatchers(HttpMethod.GET, "/api/admin").hasRole("ADMIN")
                it.anyRequest().denyAll()
            }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.jwtAuthenticationConverter(jwtConverter) } }
            .build()
    }
}

package dev.keycloak.demo.security

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("keycloak")
data class KeycloakProperties(
    val issuerUri: String,
    val apiClientId: String,
    val browserClientId: String,
)

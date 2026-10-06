package dev.keycloak.demo.security

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("keycloak")
data class KeycloakProperties(
    val issuerUri: String,
    val internalBaseUri: String,
    val apiClientId: String,
    val clientId: String,
    val clientSecret: String,
)

@ConfigurationProperties("bff")
data class BffProperties(val publicUrl: String)

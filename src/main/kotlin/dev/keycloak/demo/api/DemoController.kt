package dev.keycloak.demo.api

import dev.keycloak.demo.security.KeycloakProperties
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class DemoController(
    private val keycloak: KeycloakProperties,
) {
    @GetMapping("/public")
    fun publicInfo() = PublicInfo(
        message = "Public endpoint: no token required",
        issuerUri = keycloak.issuerUri,
        browserClientId = keycloak.browserClientId,
    )

    @GetMapping("/me")
    fun me(authentication: JwtAuthenticationToken) = UserInfo(
        subject = authentication.token.subject,
        username = authentication.token.getClaimAsString("preferred_username"),
        email = authentication.token.getClaimAsString("email"),
        roles = authentication.authorities.map { it.authority }
            .filter { it.startsWith("ROLE_") }.map { it.removePrefix("ROLE_") }.sorted(),
        scopes = authentication.authorities.map { it.authority }
            .filter { it.startsWith("SCOPE_") }.map { it.removePrefix("SCOPE_") }.sorted(),
    )

    @GetMapping("/user")
    fun user() = MessageResponse("You have the USER role in ${keycloak.apiClientId}")

    @GetMapping("/admin")
    fun admin() = MessageResponse("You have the ADMIN role in ${keycloak.apiClientId}")
}

data class PublicInfo(val message: String, val issuerUri: String, val browserClientId: String)
data class MessageResponse(val message: String)
data class UserInfo(
    val subject: String,
    val username: String?,
    val email: String?,
    val roles: List<String>,
    val scopes: List<String>,
)

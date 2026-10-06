package dev.keycloak.demo.api

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.net.URI

@RestController
@RequestMapping("/api")
class DemoController {
    @GetMapping("/auth/login")
    fun login(): ResponseEntity<Void> = ResponseEntity.status(302)
        .location(URI.create("/api/auth/authorize/keycloak")).build()

    @GetMapping("/auth/register")
    fun register(): ResponseEntity<Void> = ResponseEntity.status(302)
        .location(URI.create("/api/auth/authorize/keycloak?register=true")).build()

    @GetMapping("/public")
    fun publicInfo() = MessageResponse("Kotlin BFF: session authentication and internal CV gateway")

    @GetMapping("/auth/csrf")
    fun csrf(token: CsrfToken) = CsrfResponse(token.token, token.headerName, token.parameterName)

    @GetMapping("/me")
    fun me(authentication: OAuth2AuthenticationToken): UserInfo {
        val user = authentication.principal as OidcUser
        return UserInfo(
            subject = user.subject,
            username = user.getClaimAsString("preferred_username"),
            email = user.email,
            roles = authentication.authorities.map { it.authority }
                .filter { it.startsWith("ROLE_") }.map { it.removePrefix("ROLE_") }.sorted(),
            scopes = authentication.authorities.map { it.authority }
                .filter { it.startsWith("SCOPE_") }.map { it.removePrefix("SCOPE_") }.sorted(),
        )
    }

    @GetMapping("/user")
    fun user() = MessageResponse("You have the USER role")

    @GetMapping("/admin")
    fun admin() = MessageResponse("You have the ADMIN role")
}

data class MessageResponse(val message: String)
data class CsrfResponse(val token: String, val headerName: String, val parameterName: String)
data class UserInfo(val subject: String, val username: String?, val email: String?, val roles: List<String>, val scopes: List<String>)

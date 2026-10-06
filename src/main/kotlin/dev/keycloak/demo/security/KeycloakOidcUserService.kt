package dev.keycloak.demo.security

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser

/** Spring verifies the ID token and UserInfo subject before these claims are used. */
class KeycloakOidcUserService(private val apiClientId: String) : OAuth2UserService<OidcUserRequest, OidcUser> {
    private val delegate = OidcUserService()

    override fun loadUser(request: OidcUserRequest): OidcUser {
        val user = delegate.loadUser(request)
        val resources = user.claims["resource_access"] as? Map<*, *>
        val client = resources?.get(apiClientId) as? Map<*, *>
        val roles = (client?.get("roles") as? Collection<*>).orEmpty()
            .filterIsInstance<String>().filter { it.isNotBlank() }
            .map { SimpleGrantedAuthority("ROLE_$it") }
        return DefaultOidcUser(
            (user.authorities + roles).distinctBy { it.authority },
            user.idToken,
            user.userInfo,
            "sub",
        )
    }
}

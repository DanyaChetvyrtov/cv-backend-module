package dev.keycloak.demo.security

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter

/** Only roles belonging to this API can grant access; OAuth scopes are preserved. */
class KeycloakAuthoritiesConverter(
    private val apiClientId: String,
) : Converter<Jwt, Collection<GrantedAuthority>> {
    private val scopeConverter = JwtGrantedAuthoritiesConverter()

    override fun convert(jwt: Jwt): Collection<GrantedAuthority> {
        val resources = jwt.claims["resource_access"] as? Map<*, *>
        val client = resources?.get(apiClientId) as? Map<*, *>
        val roles = (client?.get("roles") as? Collection<*>)
            .orEmpty()
            .filterIsInstance<String>()
            .filter { it.isNotBlank() }
            .map { SimpleGrantedAuthority("ROLE_$it") }

        return (scopeConverter.convert(jwt).orEmpty() + roles).distinctBy { it.authority }
    }
}

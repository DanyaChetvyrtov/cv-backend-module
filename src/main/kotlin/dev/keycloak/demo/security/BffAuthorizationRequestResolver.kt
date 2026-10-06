package dev.keycloak.demo.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest

class BffAuthorizationRequestResolver(registrations: ClientRegistrationRepository) : OAuth2AuthorizationRequestResolver {
    private val delegate = DefaultOAuth2AuthorizationRequestResolver(registrations, "/api/auth/authorize").apply {
        setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce())
    }

    override fun resolve(request: HttpServletRequest): OAuth2AuthorizationRequest? =
        customize(request, delegate.resolve(request))

    override fun resolve(request: HttpServletRequest, clientRegistrationId: String): OAuth2AuthorizationRequest? =
        customize(request, delegate.resolve(request, clientRegistrationId))

    private fun customize(request: HttpServletRequest, resolved: OAuth2AuthorizationRequest?): OAuth2AuthorizationRequest? {
        if (resolved == null || request.getParameter("register") != "true") return resolved
        return OAuth2AuthorizationRequest.from(resolved)
            .additionalParameters { it["prompt"] = "create" }
            .build()
    }
}

package dev.keycloak.demo.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.web.client.RestClientException
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Instant

/** Refresh stays on the server; revoked/expired credentials cannot leave a live BFF session. */
class SessionRefreshFilter(private val manager: OAuth2AuthorizedClientManager) : OncePerRequestFilter() {
    override fun shouldNotFilter(request: HttpServletRequest): Boolean {
        val path = request.requestURI.removePrefix(request.contextPath)
        return !path.startsWith("/api/") || path.startsWith("/api/auth/") || path in setOf("/api/public", "/api/health")
    }

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication is OAuth2AuthenticationToken) {
            try {
                val client = manager.authorize(
                    OAuth2AuthorizeRequest.withClientRegistrationId(authentication.authorizedClientRegistrationId)
                        .principal(authentication)
                        .attribute(HttpServletRequest::class.java.name, request)
                        .attribute(HttpServletResponse::class.java.name, response)
                        .build(),
                )
                if (client == null || client.accessToken.expiresAt?.isAfter(Instant.now()) != true) {
                    expire(request, response, authentication)
                    return
                }
            } catch (exception: OAuth2AuthorizationException) {
                if (exception.error.errorCode in setOf("invalid_grant", "invalid_token")) {
                    expire(request, response, authentication)
                } else {
                    response.sendError(503, "Identity provider is unavailable")
                }
                return
            } catch (exception: RestClientException) {
                response.sendError(503, "Identity provider is unavailable")
                return
            }
        }
        chain.doFilter(request, response)
    }

    private fun expire(request: HttpServletRequest, response: HttpServletResponse, authentication: OAuth2AuthenticationToken) {
        CookieClearingLogoutHandler("BFFSESSION").logout(request, response, authentication)
        SecurityContextLogoutHandler().logout(request, response, authentication)
        response.status = 401
        response.contentType = "application/json"
        response.writer.write("{\"detail\":\"Session expired. Sign in again.\"}")
    }
}

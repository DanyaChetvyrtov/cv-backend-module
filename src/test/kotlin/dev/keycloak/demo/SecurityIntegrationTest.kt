package dev.keycloak.demo

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.net.InetSocketAddress
import java.time.Instant
import java.util.Date

/** Exercises the real decoder and filter chain, including RSA signature and claim validation. */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {
    @Autowired
    lateinit var mvc: MockMvc

    @Test
    fun `public endpoint is accessible without a token`() {
        mvc.get("/api/public").andExpect { status { isOk() } }
    }

    @Test
    fun `demo page and health are public`() {
        listOf("/", "/app.js", "/actuator/health").forEach { path ->
            mvc.get(path).andExpect { status { isOk() } }
        }
    }

    @Test
    fun `protected endpoints require authentication`() {
        listOf("/api/me", "/api/user", "/api/admin").forEach { path ->
            mvc.get(path).andExpect {
                status { isUnauthorized() }
                header { string("WWW-Authenticate", "Bearer") }
            }
        }
    }

    @Test
    fun `valid token returns profile and preserves scopes`() {
        mvc.get("/api/me") { bearer(token()) }.andExpect {
            status { isOk() }
            jsonPath("$.subject") { value("test-subject") }
            jsonPath("$.username") { value("demo") }
            jsonPath("$.email") { value("demo@example.test") }
            jsonPath("$.roles[0]") { value("USER") }
            jsonPath("$.scopes[0]") { value("openid") }
            jsonPath("$.scopes[1]") { value("profile") }
        }
    }

    @Test
    fun `USER can access user endpoint`() {
        mvc.get("/api/user") { bearer(token()) }.andExpect { status { isOk() } }
    }

    @Test
    fun `USER cannot access admin endpoint`() {
        mvc.get("/api/admin") { bearer(token()) }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `ADMIN can access admin endpoint`() {
        mvc.get("/api/admin") { bearer(token(roles = listOf("USER", "ADMIN"))) }
            .andExpect { status { isOk() } }
    }

    @Test
    fun `authentication alone does not grant a role`() {
        val jwt = token(roles = emptyList())
        mvc.get("/api/me") { bearer(jwt) }.andExpect { status { isOk() } }
        mvc.get("/api/user") { bearer(jwt) }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `roles from another client do not grant access`() {
        mvc.get("/api/admin") { bearer(token(roles = listOf("ADMIN"), roleClient = "other-api")) }
            .andExpect { status { isForbidden() } }
    }

    @Test
    fun `realm administrator role does not grant API administrator access`() {
        mvc.get("/api/admin") {
            bearer(token(roles = emptyList(), extraClaims = mapOf("realm_access" to mapOf("roles" to listOf("ADMIN")))))
        }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `missing role claims are handled as no roles`() {
        mvc.get("/api/user") { bearer(token(extraClaims = mapOf("resource_access" to null))) }
            .andExpect { status { isForbidden() } }
    }

    @Test
    fun `malformed role claims cannot grant access`() {
        mvc.get("/api/admin") {
            bearer(token(extraClaims = mapOf("resource_access" to mapOf("demo-api" to mapOf("roles" to "ADMIN")))))
        }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `wrong audience is rejected`() {
        mvc.get("/api/me") { bearer(token(audience = "demo-browser")) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `missing audience is rejected`() {
        mvc.get("/api/me") { bearer(token(audience = null)) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `wrong issuer is rejected`() {
        mvc.get("/api/me") { bearer(token(issuer = "https://untrusted.example/realms/demo")) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `expired token is rejected`() {
        mvc.get("/api/me") { bearer(token(expiresAt = Instant.now().minusSeconds(120))) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `token not yet valid is rejected`() {
        mvc.get("/api/me") { bearer(token(extraClaims = mapOf("nbf" to Date.from(Instant.now().plusSeconds(300))))) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `signature made with an untrusted key is rejected`() {
        mvc.get("/api/me") { bearer(token(signingKey = RSAKeyGenerator(2048).keyID("test-key").generate())) }
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `malformed token is rejected`() {
        mvc.get("/api/me") { bearer("not-a-jwt") }.andExpect { status { isUnauthorized() } }
    }

    private fun token(
        roles: List<String> = listOf("USER"),
        roleClient: String = "demo-api",
        audience: String? = "demo-api",
        issuer: String = ISSUER,
        expiresAt: Instant = Instant.now().plusSeconds(300),
        signingKey: RSAKey = key,
        extraClaims: Map<String, Any?> = emptyMap(),
    ): String {
        val claims = JWTClaimsSet.Builder()
            .subject("test-subject")
            .issuer(issuer)
            .issueTime(Date.from(Instant.now().minusSeconds(300)))
            .expirationTime(Date.from(expiresAt))
            .claim("preferred_username", "demo")
            .claim("email", "demo@example.test")
            .claim("scope", "openid profile")
            .claim("resource_access", mapOf(roleClient to mapOf("roles" to roles)))
        audience?.let { claims.audience(it) }
        extraClaims.forEach { (name, value) -> claims.claim(name, value) }
        return SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.keyID).type(JOSEObjectType.JWT).build(),
            claims.build(),
        ).apply { sign(RSASSASigner(signingKey)) }.serialize()
    }

    private fun org.springframework.test.web.servlet.MockHttpServletRequestDsl.bearer(token: String) {
        header("Authorization", "Bearer $token")
    }

    companion object {
        private const val ISSUER = "http://localhost:8081/realms/demo"
        private val key = RSAKeyGenerator(2048).keyID("test-key").generate()
        private val jwksServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/certs") { exchange ->
                val bytes = JWKSet(key.toPublicJWK()).toString().toByteArray()
                exchange.responseHeaders.set("Content-Type", "application/json")
                exchange.sendResponseHeaders(200, bytes.size.toLong())
                exchange.responseBody.use { it.write(bytes) }
            }
            start()
        }

        @JvmStatic
        @DynamicPropertySource
        fun jwtProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri") {
                "http://127.0.0.1:${jwksServer.address.port}/certs"
            }
            registry.add("keycloak.issuer-uri") { ISSUER }
        }

        @JvmStatic
        @AfterAll
        fun stopJwksServer() {
            jwksServer.stop(0)
        }
    }
}

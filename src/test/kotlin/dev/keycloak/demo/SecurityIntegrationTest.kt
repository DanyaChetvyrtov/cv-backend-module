package dev.keycloak.demo

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.keycloak.demo.employees.EmployeeService
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockHttpSession
import org.springframework.mock.web.MockMultipartFile
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.multipart
import org.springframework.test.web.servlet.post
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/** Real OIDC filter chain, token exchange, session security and employee face verification. */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SecurityIntegrationTest {
    @Autowired lateinit var mvc: MockMvc
    @Autowired lateinit var clients: OAuth2AuthorizedClientRepository
    @Autowired lateinit var jdbc: JdbcTemplate
    @Autowired lateinit var employees: EmployeeService

    @BeforeEach
    fun resetEmployees() {
        jdbc.update("DELETE FROM employees")
        faceStatus.set(200)
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to vector(0)))
    }

    @Test
    fun `public routes do not expose OAuth configuration or tokens`() {
        mvc.get("/api/public").andExpect {
            status { isOk() }
            jsonPath("$.issuerUri") { doesNotExist() }
            jsonPath("$.clientSecret") { doesNotExist() }
        }
        mvc.get("/actuator/health").andExpect { status { isOk() } }
        mvc.get("/api/health").andExpect { status { isOk() }; jsonPath("$.status") { value("ok") } }
    }

    @Test
    fun `protected routes require a session and reject a browser bearer token`() {
        for (path in listOf("/api/me", "/api/user", "/api/admin")) {
            mvc.get(path).andExpect { status { isUnauthorized() } }
            mvc.get(path) { header("Authorization", "Bearer unused-token") }.andExpect { status { isUnauthorized() } }
        }
    }

    @Test
    fun `browser login and registration routes hide provider details`() {
        mvc.get("/api/auth/login").andExpect { redirectedUrl("/api/auth/authorize/keycloak") }
        mvc.get("/api/auth/register").andExpect { redirectedUrl("/api/auth/authorize/keycloak?register=true") }
    }

    @Test
    fun `BFF starts confidential authorization with state nonce and PKCE`() {
        val result = mvc.get("/api/auth/authorize/keycloak") { header("Host", "untrusted.example") }
            .andExpect { status { isFound() } }.andReturn()
        val params = query(result.response.redirectedUrl!!)
        assertEquals("demo-bff", params["client_id"])
        assertEquals(PUBLIC_URL + "/api/auth/callback/keycloak", params["redirect_uri"])
        assertEquals("S256", params["code_challenge_method"])
        assertFalse(params["state"].isNullOrBlank())
        assertFalse(params["nonce"].isNullOrBlank())
        assertFalse(params.containsKey("client_secret"))
        assertFalse(params.containsKey("code_verifier"))
    }

    @Test
    fun `registration is a BFF authorization redirect with prompt create`() {
        val result = mvc.get("/api/auth/authorize/keycloak?register=true").andReturn()
        assertEquals("create", query(result.response.redirectedUrl!!)["prompt"])
    }

    @Test
    fun `real OIDC login rotates session and returns only profile data`() {
        val session = login()
        mvc.get("/api/me") { this.session = session }.andExpect {
            status { isOk() }
            jsonPath("$.subject") { value("demo") }
            jsonPath("$.username") { value("demo") }
            jsonPath("$.roles[0]") { value("USER") }
            jsonPath("$.accessToken") { doesNotExist() }
            jsonPath("$.refreshToken") { doesNotExist() }
            jsonPath("$.idToken") { doesNotExist() }
        }
        mvc.get("/api/me") { this.session = session }.andExpect { status { isOk() } }
    }

    @Test
    fun `user and admin authorization are isolated between sessions`() {
        val user = login()
        val admin = login("manager", listOf("USER", "ADMIN"))
        mvc.get("/api/user") { session = user }.andExpect { status { isOk() } }
        mvc.get("/api/admin") { session = user }.andExpect { status { isForbidden() } }
        mvc.get("/api/admin") { session = admin }.andExpect { status { isOk() } }
        mvc.get("/api/me") { session = user }.andExpect { jsonPath("$.username") { value("demo") } }
    }

    @Test
    fun `foreign client roles and realm administrator cannot grant BFF privileges`() {
        val session = login(overrides = mapOf(
            "resource_access" to mapOf("other-client" to mapOf("roles" to listOf("ADMIN"))),
            "realm_access" to mapOf("roles" to listOf("ADMIN")),
        ))
        mvc.get("/api/me") { this.session = session }.andExpect { status { isOk() } }
        mvc.get("/api/admin") { this.session = session }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `malformed role claims do not grant privileges`() {
        val session = login(overrides = mapOf("resource_access" to mapOf("demo-api" to mapOf("roles" to "ADMIN"))))
        mvc.get("/api/admin") { this.session = session }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `callback without matching state cannot authenticate`() {
        val result = mvc.get("/api/auth/authorize/keycloak").andReturn()
        val session = result.request.session as MockHttpSession
        mvc.get("/api/auth/callback/keycloak?state=wrong&code=unused") { this.session = session }
            .andExpect { redirectedUrl(PUBLIC_URL + "/?auth=error") }
        mvc.get("/api/me") { this.session = session }.andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `wrong issuer wrong audience expired ID token wrong nonce and forged signature are rejected`() {
        val invalid = listOf(
            mapOf<String, Any>("iss" to "https://untrusted.example/realms/demo"),
            mapOf<String, Any>("aud" to "other-client"),
            mapOf<String, Any>("exp" to Date.from(Instant.now().minusSeconds(300))),
            mapOf<String, Any>("nonce" to "wrong-nonce"),
        )
        invalid.forEach { login(overrides = it, succeeds = false) }
        login(signingKey = RSAKeyGenerator(2048).keyID("untrusted").generate(), succeeds = false)
    }


    @Test
    fun `GET logout does not terminate a session`() {
        val session = login()
        mvc.get("/api/auth/logout") { this.session = session }.andExpect { status { isForbidden() } }
        mvc.get("/api/me") { this.session = session }.andExpect { status { isOk() } }
    }

    @Test
    fun `POST logout clears local session cookie and redirects to provider logout`() {
        val session = login()
        val result = mvc.post("/api/auth/logout") { this.session = session; header("X-CSRF-TOKEN", csrf(session)) }
            .andExpect { status { isFound() }; cookie { maxAge("BFFSESSION", 0) } }.andReturn()
        assertTrue(session.isInvalid)
        assertTrue(result.response.redirectedUrl!!.startsWith(ISSUER + "/protocol/openid-connect/logout?"))
        assertEquals(PUBLIC_URL + "/", query(result.response.redirectedUrl!!)["post_logout_redirect_uri"])
        mvc.get("/api/me").andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `expired access token is refreshed on the server`() {
        val session = login()
        expireAccessToken(session)
        val before = refreshCount.get()
        mvc.get("/api/me") { this.session = session }.andExpect { status { isOk() } }
        assertEquals(before + 1, refreshCount.get())
    }

    @Test
    fun `revoked refresh token invalidates the BFF session`() {
        val session = login()
        val refresh = expireAccessToken(session)
        revokedRefreshTokens.add(refresh)
        mvc.get("/api/me") { this.session = session }.andExpect { status { isUnauthorized() } }
        assertTrue(session.isInvalid)
    }

    @Test
    fun `employee registry is admin only and identification requires USER with CSRF`() {
        mvc.get("/api/employees").andExpect { status { isUnauthorized() } }
        val user = login()
        mvc.get("/api/employees") { session = user }.andExpect { status { isForbidden() } }
        register(user).andExpect { status { isForbidden() } }
        mvc.delete("/api/employees/${UUID.randomUUID()}") { session = user; header("X-CSRF-TOKEN", csrf(user)) }
            .andExpect { status { isForbidden() } }
        val admin = login("manager", listOf("USER", "ADMIN"))
        mvc.multipart("/api/employees") { session = admin; file(image()); param("employeeCode", "EMP-1"); param("fullName", "Name") }
            .andExpect { status { isForbidden() } }
        mvc.multipart("/api/employees/identifications") { session = user; file(image()) }
            .andExpect { status { isForbidden() } }
        val anonymous = mvc.get("/api/auth/csrf").andReturn().request.session as MockHttpSession
        identify(anonymous).andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `register identify list paginate and delete employee without exposing biometrics`() {
        val admin = login("manager", listOf("USER", "ADMIN"))
        val created = register(admin, " emp-1 ").andExpect {
            status { isCreated() }
            jsonPath("$.employeeCode") { value("EMP-1") }
            jsonPath("$.faceEmbedding") { doesNotExist() }
            jsonPath("$.embedding") { doesNotExist() }
            jsonPath("$.model") { doesNotExist() }
        }.andReturn()
        val id = mapper.readTree(created.response.contentAsString)["id"].asText()
        assertEquals("/api/employees/$id", created.response.getHeader("Location"))
        mvc.get("/api/employees?page=0&size=1") { session = admin }.andExpect {
            status { isOk() }; jsonPath("$.total") { value(1) }; jsonPath("$.items[0].fullName") { value("Demo Worker") }
            jsonPath("$.items[0].faceEmbedding") { doesNotExist() }
        }
        mvc.get("/api/employees?page=1&size=1") { session = admin }.andExpect { jsonPath("$.items.length()") { value(0) } }
        mvc.get("/api/employees?size=101") { session = admin }.andExpect { status { isBadRequest() } }
        val user = login()
        identify(user).andExpect {
            status { isOk() }; jsonPath("$.status") { value("matched") }; jsonPath("$.employee.id") { value(id) }
            jsonPath("$.embedding") { doesNotExist() }
        }
        assertNull(lastFaceCookie.get()); assertNull(lastFaceAuthorization.get())
        mvc.delete("/api/employees/$id") { session = admin }.andExpect { status { isForbidden() } }
        mvc.delete("/api/employees/$id") { session = admin; header("X-CSRF-TOKEN", csrf(admin)) }.andExpect { status { isNoContent() } }
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM employees", Int::class.java))
        identify(user).andExpect { jsonPath("$.status") { value("unknown") }; jsonPath("$.employee") { isEmpty() } }
        mvc.delete("/api/employees/$id") { session = admin; header("X-CSRF-TOKEN", csrf(admin)) }.andExpect { status { isNotFound() } }
    }

    @Test
    fun `unknown faces and close candidates never expose an employee identity`() {
        val admin = login("manager", listOf("USER", "ADMIN"))
        register(admin).andExpect { status { isCreated() } }
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to vector(1)))
        register(admin, "EMP-2").andExpect { status { isCreated() } }
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to vector(2)))
        identify(admin).andExpect { jsonPath("$.status") { value("unknown") }; jsonPath("$.employee") { isEmpty() } }
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to List(128) { if (it < 2) 1.0 else 0.0 }))
        identify(admin).andExpect { jsonPath("$.status") { value("ambiguous") }; jsonPath("$.employee") { isEmpty() } }
    }

    @Test
    fun `duplicate employee codes or faces are rejected without changing the registry`() {
        val admin = login("manager", listOf("USER", "ADMIN"))
        register(admin).andExpect { status { isCreated() } }
        register(admin, "EMP-2").andExpect { status { isConflict() } }
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to vector(1)))
        register(admin).andExpect { status { isConflict() } }
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM employees", Int::class.java))
        register(admin, "bad code").andExpect { status { isBadRequest() } }
    }

    @Test
    fun `simultaneous registrations cannot create duplicate face templates`() {
        val pool = Executors.newFixedThreadPool(2)
        try {
            val outcomes = pool.invokeAll(listOf("CONCURRENT-1", "CONCURRENT-2").map { code -> Callable {
                try { employees.create(code, "Worker", null, image()); 201 }
                catch (exception: org.springframework.web.server.ResponseStatusException) { exception.statusCode.value() }
            } }).map { it.get() }.sorted()
            assertEquals(listOf(201, 409), outcomes)
            assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM employees", Int::class.java))
        } finally { pool.shutdownNow() }
    }

    @Test
    fun `invalid face data failed inference and changed models do not become negative matches`() {
        val admin = login("manager", listOf("USER", "ADMIN"))
        faceStatus.set(422)
        register(admin).andExpect { status { isUnprocessableEntity() }; jsonPath("$.detail") { value("exactly one face required") } }
        faceStatus.set(503)
        identify(admin).andExpect { status { isServiceUnavailable() } }
        faceStatus.set(200)
        for (embedding in listOf(emptyList(), List(128) { 0.0 })) {
            faceReply.set(mapOf("model" to "sface-fixture", "embedding" to embedding))
            register(admin).andExpect { status { isBadGateway() } }
        }
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM employees", Int::class.java))
        faceReply.set(mapOf("model" to "sface-fixture", "embedding" to vector(0)))
        register(admin).andExpect { status { isCreated() } }
        faceReply.set(mapOf("model" to "another-model", "embedding" to vector(0)))
        identify(admin).andExpect { status { isServiceUnavailable() } }
        register(admin, "EMP-2").andExpect { status { isServiceUnavailable() } }
    }

    private fun register(session: MockHttpSession, code: String = "EMP-1") = mvc.multipart("/api/employees") {
        this.session = session; file(image()); param("employeeCode", code); param("fullName", "Demo Worker")
        header("X-CSRF-TOKEN", csrf(session))
    }

    private fun identify(session: MockHttpSession) = mvc.multipart("/api/employees/identifications") {
        this.session = session; file(image()); header("X-CSRF-TOKEN", csrf(session))
    }

    private fun image() = MockMultipartFile("image", "photo.png", "image/png", "sample-image".toByteArray())

    private fun csrf(session: MockHttpSession): String = mapper.readTree(
        mvc.get("/api/auth/csrf") { this.session = session }.andReturn().response.contentAsString,
    )["token"].asText()

    private fun expireAccessToken(session: MockHttpSession): String {
        val result = mvc.get("/api/me") { this.session = session }.andReturn()
        val auth = (session.getAttribute("SPRING_SECURITY_CONTEXT") as SecurityContext).authentication as OAuth2AuthenticationToken
        val client = clients.loadAuthorizedClient<OAuth2AuthorizedClient>("keycloak", auth, result.request)!!
        val expired = OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, client.accessToken.tokenValue,
            Instant.now().minusSeconds(600), Instant.now().minusSeconds(120), client.accessToken.scopes)
        clients.saveAuthorizedClient(OAuth2AuthorizedClient(client.clientRegistration, client.principalName, expired, client.refreshToken),
            auth, result.request, result.response)
        return client.refreshToken!!.tokenValue
    }

    private fun login(
        username: String = "demo",
        roles: List<String> = listOf("USER"),
        overrides: Map<String, Any> = emptyMap(),
        signingKey: RSAKey = key,
        succeeds: Boolean = true,
    ): MockHttpSession {
        val start = mvc.get("/api/auth/authorize/keycloak").andExpect { status { isFound() } }.andReturn()
        val session = start.request.session as MockHttpSession
        val originalId = session.id
        val params = query(start.response.redirectedUrl!!)
        val code = UUID.randomUUID().toString()
        grants[code] = Grant(username, roles, params["nonce"]!!, params["code_challenge"]!!, overrides, signingKey)
        val callback = mvc.get("/api/auth/callback/keycloak") {
            this.session = session; param("state", params["state"]!!); param("code", code)
        }.andExpect { redirectedUrl(if (succeeds) PUBLIC_URL + "/" else PUBLIC_URL + "/?auth=error") }.andReturn()
        if (succeeds) assertNotEquals(originalId, session.id, "Session fixation protection")
        else mvc.get("/api/me") { this.session = session }.andExpect { status { isUnauthorized() } }
        return callback.request.session as MockHttpSession
    }

    private data class Grant(val username: String, val roles: List<String>, val nonce: String, val challenge: String,
        val overrides: Map<String, Any>, val key: RSAKey)

    companion object {
        private const val PUBLIC_URL = "http://127.0.0.1:5173"
        private val mapper = ObjectMapper()
        private val key = RSAKeyGenerator(2048).keyID("test-key").generate()
        private val grants = ConcurrentHashMap<String, Grant>()
        private val tokenUsers = ConcurrentHashMap<String, Grant>()
        private val revokedRefreshTokens = ConcurrentHashMap.newKeySet<String>()
        private val refreshCount = AtomicInteger()
        private val cvStatus = AtomicInteger(200)
        private val lastCvBody = AtomicReference("")
        private val lastCvQuery = AtomicReference("")
        private val lastCvCookie = AtomicReference<String?>()
        private val lastCvAuthorization = AtomicReference<String?>()
        private val faceStatus = AtomicInteger(200)
        private val faceReply = AtomicReference<Map<String, Any>>(emptyMap())
        private val lastFaceCookie = AtomicReference<String?>()
        private val lastFaceAuthorization = AtomicReference<String?>()
        private fun vector(axis: Int): List<Double> = List(128) { if (it == axis) 1.0 else 0.0 }
        private val oidc = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        private val ISSUER = "http://127.0.0.1:" + oidc.address.port + "/realms/demo"
        private val cv = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)

        init {
            oidc.createContext("/realms/demo/protocol/openid-connect/certs") { reply(it, 200, JWKSet(key.toPublicJWK()).toJSONObject()) }
            oidc.createContext("/realms/demo/protocol/openid-connect/token") { exchange ->
                val form = parse(exchange.requestBody.readAllBytes().toString(UTF_8))
                val expected = "Basic " + Base64.getEncoder().encodeToString("demo-bff:local-bff-secret".toByteArray())
                if (exchange.requestHeaders.getFirst("Authorization") != expected) {
                    reply(exchange, 401, mapOf("error" to "invalid_client"))
                } else if (form["grant_type"] == "refresh_token") {
                    val refresh = form["refresh_token"] ?: ""
                    val grant = tokenUsers[refresh]
                    if (grant == null || revokedRefreshTokens.contains(refresh)) reply(exchange, 400, mapOf("error" to "invalid_grant"))
                    else { refreshCount.incrementAndGet(); reply(exchange, 200, tokens(grant)) }
                } else {
                    val grant = grants.remove(form["code"] ?: "")
                    val verifier = form["code_verifier"] ?: ""
                    val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
                    if (grant == null || challenge != grant.challenge || form["redirect_uri"] != PUBLIC_URL + "/api/auth/callback/keycloak") {
                        reply(exchange, 400, mapOf("error" to "invalid_grant"))
                    } else reply(exchange, 200, tokens(grant))
                }
            }
            oidc.createContext("/realms/demo/protocol/openid-connect/userinfo") { exchange ->
                val grant = tokenUsers[exchange.requestHeaders.getFirst("Authorization")?.removePrefix("Bearer ") ?: ""]
                if (grant == null) reply(exchange, 401, mapOf("error" to "invalid_token"))
                else reply(exchange, 200, mapOf("sub" to grant.username, "preferred_username" to grant.username,
                    "email" to grant.username + "@example.test", "resource_access" to mapOf("demo-api" to mapOf("roles" to grant.roles))) +
                    grant.overrides.filterKeys { it in setOf("resource_access", "realm_access") })
            }
            oidc.start()
            cv.createContext("/health") { reply(it, 200, mapOf("status" to "ok", "model" to "fixture", "device" to "cpu")) }
            cv.createContext("/faces/embedding") { exchange ->
                exchange.requestBody.readAllBytes()
                lastFaceCookie.set(exchange.requestHeaders.getFirst("Cookie"))
                lastFaceAuthorization.set(exchange.requestHeaders.getFirst("Authorization"))
                if (faceStatus.get() == 200) reply(exchange, 200, faceReply.get())
                else reply(exchange, faceStatus.get(), mapOf("detail" to "exactly one face required"))
            }
            cv.start()
        }

        private fun tokens(grant: Grant): Map<String, Any> {
            val access = UUID.randomUUID().toString()
            val refresh = UUID.randomUUID().toString()
            tokenUsers[access] = grant; tokenUsers[refresh] = grant
            val claims = JWTClaimsSet.Builder().subject(grant.username).issuer(ISSUER).audience("demo-bff")
                .issueTime(Date.from(Instant.now().minusSeconds(1))).expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", grant.nonce).claim("preferred_username", grant.username).claim("email", grant.username + "@example.test")
                .claim("resource_access", mapOf("demo-api" to mapOf("roles" to grant.roles)))
            grant.overrides.forEach { (name, value) -> claims.claim(name, value) }
            val id = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(grant.key.keyID).build(), claims.build())
                .apply { sign(RSASSASigner(grant.key)) }.serialize()
            return mapOf("access_token" to access, "refresh_token" to refresh, "id_token" to id,
                "token_type" to "Bearer", "expires_in" to 300, "scope" to "openid profile email")
        }

        private fun reply(exchange: HttpExchange, status: Int, body: Any) {
            val bytes = mapper.writeValueAsBytes(body)
            exchange.responseHeaders.set("Content-Type", "application/json")
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }

        private fun parse(value: String): Map<String, String> = value.split('&').filter { it.contains('=') }.associate {
            val pair = it.split('=', limit = 2)
            URLDecoder.decode(pair[0], UTF_8) to URLDecoder.decode(pair[1], UTF_8)
        }
        private fun query(url: String): Map<String, String> = parse(URI.create(url).rawQuery ?: "")

        @JvmStatic @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("keycloak.issuer-uri") { ISSUER }
            registry.add("keycloak.internal-base-uri") { ISSUER }
            registry.add("vision.base-url") { "http://127.0.0.1:" + cv.address.port }
        }
        @JvmStatic @AfterAll
        fun stopServers() { oidc.stop(0); cv.stop(0) }
    }
}

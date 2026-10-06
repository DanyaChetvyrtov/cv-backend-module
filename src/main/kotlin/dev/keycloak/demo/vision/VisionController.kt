package dev.keycloak.demo.vision

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.ResourceAccessException
import org.springframework.web.client.RestClient
import org.springframework.web.server.ResponseStatusException
import org.springframework.http.HttpStatus
import java.nio.charset.StandardCharsets
import java.time.Duration

@RestController
@RequestMapping("/api")
class VisionController(@Value("\${vision.base-url}") baseUrl: String) {
    private val client = RestClient.builder().baseUrl(baseUrl).requestFactory(
        SimpleClientHttpRequestFactory().apply {
            setConnectTimeout(Duration.ofSeconds(5))
            setReadTimeout(Duration.ofSeconds(30))
        },
    ).build()

    @GetMapping("/health")
    fun health(): ResponseEntity<String> = forward(client.get().uri("/health"))

    private fun forward(request: RestClient.RequestHeadersSpec<*>): ResponseEntity<String> = try {
        request.exchange { _, response ->
            ResponseEntity.status(response.statusCode)
                .contentType(response.headers.contentType ?: MediaType.APPLICATION_JSON)
                .body(response.body.readAllBytes().toString(StandardCharsets.UTF_8))
        } ?: throw ResponseStatusException(HttpStatus.BAD_GATEWAY, "Empty response from CV service")
    } catch (exception: ResourceAccessException) {
        throw ResponseStatusException(HttpStatus.BAD_GATEWAY, "CV service is unavailable")
    }
}

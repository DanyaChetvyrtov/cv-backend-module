package dev.keycloak.demo.vision

import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ByteArrayResource
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestPart
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.ResourceAccessException
import org.springframework.web.client.RestClient
import org.springframework.web.multipart.MultipartFile
import org.springframework.web.server.ResponseStatusException
import java.nio.charset.StandardCharsets
import java.time.Duration

/** Only these two fixed routes are forwarded; cookies/tokens never reach the CV service. */
@RestController
@RequestMapping("/api")
class VisionController(@Value("\${vision.base-url}") baseUrl: String) {
    private val client = RestClient.builder().baseUrl(baseUrl).requestFactory(
        SimpleClientHttpRequestFactory().apply {
            setConnectTimeout(Duration.ofSeconds(5))
            setReadTimeout(Duration.ofSeconds(120))
        },
    ).build()

    @GetMapping("/health")
    fun health(): ResponseEntity<String> = forward(client.get().uri("/health"))

    @PostMapping("/vision/detect", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    fun detect(@RequestPart("image") image: MultipartFile, @RequestParam(defaultValue = "0.25") confidence: Double): ResponseEntity<String> {
        if (!confidence.isFinite() || confidence !in 0.01..1.0) {
            throw ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Confidence must be between 0.01 and 1.0")
        }
        if (image.isEmpty) throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Image is empty")
        val body = LinkedMultiValueMap<String, Any>().apply {
            add("image", object : ByteArrayResource(image.bytes) {
                override fun getFilename() = "upload"
            })
        }
        return forward(client.post().uri { it.path("/vision/detect").queryParam("confidence", confidence).build() }
            .contentType(MediaType.MULTIPART_FORM_DATA).body(body))
    }

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

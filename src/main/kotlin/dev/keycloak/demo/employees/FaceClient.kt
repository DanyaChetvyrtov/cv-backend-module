package dev.keycloak.demo.employees

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.ByteArrayResource
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.client.SimpleClientHttpRequestFactory
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import org.springframework.web.multipart.MultipartFile
import org.springframework.web.server.ResponseStatusException
import java.time.Duration

@Component
class FaceClient(@Value("\${vision.base-url}") baseUrl: String, private val mapper: ObjectMapper) {
    private val client = RestClient.builder().baseUrl(baseUrl).requestFactory(SimpleClientHttpRequestFactory().apply {
        setConnectTimeout(Duration.ofSeconds(5))
        setReadTimeout(Duration.ofSeconds(30))
    }).build()

    internal fun extract(image: MultipartFile): Pair<String, FloatArray> {
        if (image.isEmpty) throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Image is empty")
        val body = LinkedMultiValueMap<String, Any>().apply {
            add("image", object : ByteArrayResource(image.bytes) { override fun getFilename() = "upload" })
        }
        try {
            val vector = client.post().uri("/faces/embedding").contentType(MediaType.MULTIPART_FORM_DATA).body(body)
                .exchange { _, response ->
                    if (!response.statusCode.is2xxSuccessful) {
                        val status = response.statusCode.value()
                        if (status in setOf(400, 413, 415, 422)) {
                            val detail = runCatching { mapper.readTree(response.body)["detail"]?.asText() }.getOrNull()
                            throw ResponseStatusException(HttpStatus.valueOf(status), detail ?: "Invalid face photo")
                        }
                        throw ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Face recognition is unavailable")
                    }
                    mapper.readValue(response.body, FaceVector::class.java)
                } ?: throw ResponseStatusException(HttpStatus.BAD_GATEWAY, "Invalid response from CV")
            if (vector.model.isBlank() || vector.model.length > 100) throw IllegalArgumentException("Invalid face model")
            return vector.model to FaceVectors.normalize(vector.embedding)
        } catch (exception: ResponseStatusException) {
            throw exception
        } catch (exception: RestClientException) {
            throw ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Face recognition is unavailable")
        } catch (exception: Exception) {
            throw ResponseStatusException(HttpStatus.BAD_GATEWAY, "Invalid face recognition response")
        }
    }
}

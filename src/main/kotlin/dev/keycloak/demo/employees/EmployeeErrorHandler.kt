package dev.keycloak.demo.employees

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.server.ResponseStatusException

@RestControllerAdvice(assignableTypes = [EmployeeController::class])
class EmployeeErrorHandler {
    @ExceptionHandler(ResponseStatusException::class)
    fun failure(exception: ResponseStatusException): ResponseEntity<Map<String, String>> =
        ResponseEntity.status(exception.statusCode).body(mapOf("detail" to (exception.reason ?: "Employee request failed")))
}

package dev.keycloak.demo.employees

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.transaction.support.TransactionTemplate
import org.springframework.web.multipart.MultipartFile
import org.springframework.web.server.ResponseStatusException
import java.time.Instant
import java.util.Locale
import java.util.UUID

@Service
@EnableConfigurationProperties(EmployeeProperties::class)
class EmployeeService(
    private val repository: EmployeeRepository,
    private val faces: FaceClient,
    private val transactions: TransactionTemplate,
    private val properties: EmployeeProperties,
) {
    fun list(page: Int, size: Int): EmployeePage {
        if (page < 0 || size !in 1..100) throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid pagination")
        return repository.page(page, size)
    }

    fun create(code: String, name: String, department: String?, image: MultipartFile): Employee {
        val employeeCode = code.trim().uppercase(Locale.ROOT)
        val fullName = name.trim()
        val unit = department?.trim()?.takeIf { it.isNotEmpty() }
        if (!employeeCode.matches(Regex("[A-Z0-9_-]{1,64}")) || fullName.length !in 1..160 || (unit?.length ?: 0) > 120) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide a name and an employee code (letters, digits, underscore or hyphen)")
        }
        val (model, vector) = faces.extract(image)
        val employee = Employee(UUID.randomUUID(), employeeCode, fullName, unit, Instant.now())
        try {
            return transactions.execute {
                // This database lock prevents concurrent registration of the same face under different codes.
                repository.lockRegistry()
                val enrolled = compatibleFaces(model)
                if (enrolled.any { FaceVectors.similarity(vector, it.embedding) >= properties.similarityThreshold }) {
                    throw ResponseStatusException(HttpStatus.CONFLICT, "This face is already registered")
                }
                repository.insert(employee, model, vector)
                employee
            }!!
        } catch (exception: DataIntegrityViolationException) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "This employee code is already registered")
        }
    }

    fun identify(image: MultipartFile): Identification {
        val (model, vector) = faces.extract(image)
        val candidates = compatibleFaces(model).map { it.employee to FaceVectors.similarity(vector, it.embedding) }
            .sortedByDescending { it.second }
        val best = candidates.firstOrNull()
        val threshold = properties.similarityThreshold
        if (best == null || best.second < threshold) return Identification("unknown", null, best?.second, threshold)
        val runnerUp = candidates.getOrNull(1)
        if (runnerUp != null && best.second - runnerUp.second < properties.ambiguityMargin) {
            return Identification("ambiguous", null, best.second, threshold)
        }
        return Identification("matched", best.first, best.second, threshold)
    }

    fun delete(id: UUID) {
        transactions.executeWithoutResult {
            repository.lockRegistry()
            if (!repository.delete(id)) throw ResponseStatusException(HttpStatus.NOT_FOUND, "Employee not found")
        }
    }

    private fun compatibleFaces(model: String): List<EnrolledFace> = repository.faces().also { enrolled ->
        if (enrolled.any { it.model != model }) {
            throw ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Face model has changed; employees need re-enrollment")
        }
    }
}

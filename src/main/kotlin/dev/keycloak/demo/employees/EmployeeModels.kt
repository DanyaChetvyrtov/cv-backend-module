package dev.keycloak.demo.employees

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Instant
import java.util.UUID

data class Employee(val id: UUID, val employeeCode: String, val fullName: String, val department: String?, val createdAt: Instant)
data class EmployeePage(val items: List<Employee>, val total: Long, val page: Int, val size: Int)
data class Identification(val status: String, val employee: Employee?, val similarity: Double?, val threshold: Double)
internal data class EnrolledFace(val employee: Employee, val model: String, val embedding: FloatArray)
internal data class FaceVector(val model: String, val embedding: List<Double>)

@ConfigurationProperties("employees")
data class EmployeeProperties(val similarityThreshold: Double = 0.5, val ambiguityMargin: Double = 0.05) {
    init {
        require(similarityThreshold.isFinite() && similarityThreshold in 0.01..1.0)
        require(ambiguityMargin.isFinite() && ambiguityMargin in 0.0..1.0)
    }
}

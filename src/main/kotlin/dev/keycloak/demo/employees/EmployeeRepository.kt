package dev.keycloak.demo.employees

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.sql.ResultSet
import java.sql.Timestamp
import java.util.UUID

@Repository
class EmployeeRepository(private val jdbc: JdbcTemplate) {
    fun page(page: Int, size: Int): EmployeePage = EmployeePage(
        jdbc.query("SELECT * FROM employees ORDER BY created_at DESC, id LIMIT ? OFFSET ?", { rs, _ -> employee(rs) }, size, page.toLong() * size),
        jdbc.queryForObject("SELECT COUNT(*) FROM employees", Long::class.java) ?: 0,
        page, size,
    )

    internal fun faces(): List<EnrolledFace> = jdbc.query("SELECT * FROM employees", { rs, _ ->
        EnrolledFace(employee(rs), rs.getString("face_model"), FaceVectors.decode(rs.getBytes("face_embedding")))
    })

    fun lockRegistry() {
        jdbc.queryForObject("SELECT id FROM employee_registry_lock WHERE id = 1 FOR UPDATE", Int::class.java)
    }

    internal fun insert(employee: Employee, model: String, vector: FloatArray) {
        jdbc.update("INSERT INTO employees (id, employee_code, full_name, department, face_model, face_embedding, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            employee.id, employee.employeeCode, employee.fullName, employee.department, model, FaceVectors.encode(vector), Timestamp.from(employee.createdAt))
    }

    fun delete(id: UUID): Boolean = jdbc.update("DELETE FROM employees WHERE id = ?", id) == 1

    private fun employee(rs: ResultSet) = Employee(
        rs.getObject("id", UUID::class.java), rs.getString("employee_code"), rs.getString("full_name"),
        rs.getString("department"), rs.getTimestamp("created_at").toInstant(),
    )
}

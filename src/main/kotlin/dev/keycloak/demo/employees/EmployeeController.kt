package dev.keycloak.demo.employees

import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestPart
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.net.URI
import java.util.UUID

@RestController
@RequestMapping("/api/employees")
class EmployeeController(private val service: EmployeeService) {
    @GetMapping
    fun list(@RequestParam(defaultValue = "0") page: Int, @RequestParam(defaultValue = "20") size: Int) = service.list(page, size)

    @PostMapping(consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    fun create(@RequestParam employeeCode: String, @RequestParam fullName: String, @RequestParam(required = false) department: String?, @RequestPart image: MultipartFile): ResponseEntity<Employee> {
        val employee = service.create(employeeCode, fullName, department, image)
        return ResponseEntity.created(URI.create("/api/employees/${employee.id}")).body(employee)
    }

    @PostMapping("/identifications", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
    fun identify(@RequestPart image: MultipartFile) = service.identify(image)

    @DeleteMapping("/{id}")
    fun delete(@PathVariable id: UUID): ResponseEntity<Void> {
        service.delete(id)
        return ResponseEntity.noContent().build()
    }
}

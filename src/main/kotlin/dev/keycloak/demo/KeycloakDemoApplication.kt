package dev.keycloak.demo

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class KeycloakDemoApplication

fun main(args: Array<String>) {
    runApplication<KeycloakDemoApplication>(*args)
}

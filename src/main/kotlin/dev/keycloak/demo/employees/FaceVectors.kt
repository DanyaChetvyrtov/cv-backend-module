package dev.keycloak.demo.employees

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.sqrt

internal object FaceVectors {
    fun normalize(values: List<Double>): FloatArray {
        require(values.size == 128 && values.all { it.isFinite() }) { "Invalid face embedding" }
        val norm = sqrt(values.sumOf { it * it })
        require(norm.isFinite() && norm > 1e-8) { "Invalid face embedding norm" }
        return FloatArray(128) { (values[it] / norm).toFloat() }
    }

    fun similarity(first: FloatArray, second: FloatArray): Double {
        require(first.size == 128 && second.size == 128)
        return first.indices.sumOf { first[it].toDouble() * second[it] }.coerceIn(-1.0, 1.0)
    }

    fun encode(values: FloatArray): ByteArray = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN).apply {
        values.forEach { putFloat(it) }
    }.array()

    fun decode(bytes: ByteArray): FloatArray {
        require(bytes.size == 512) { "Invalid stored embedding length" }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        return normalize(List(128) { buffer.float.toDouble() })
    }
}

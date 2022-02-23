package co.luckywolf.arrow

import arrow.core.*
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import co.luckywolf.arrow.EitherStructures as eithers

class ArrowStructureTests {

    @Test
    fun right() {
        val right = eithers.right()
        assertTrue(right.isRight())
    }

    @Test
    fun left() {
        val left = eithers.left()
        assertFalse(left.isRight())
    }

    @Test
    fun rightLeft() {

        val rightLeft = eithers.rightOrLeft(true)

        val result = rightLeft.map {
            it.right
        }.orNull()

        assertTrue(result == "right")

        val direction: String = when (rightLeft) {
            is Either.Right -> rightLeft.value.right
            is Either.Left -> rightLeft.value.left
            else -> "boom"
        }
        assertTrue(direction == "right")
    }

    @Test
    fun leftRight() {

        val rightLeft = eithers.rightOrLeft(false)

        val result = rightLeft.map {
            it.right
        }.orNull()

        assertNull(result)

        val direction: String = when (rightLeft) {
            is Either.Right -> rightLeft.value.right
            is Either.Left -> rightLeft.value.left
            else -> "boom"
        }
        assertTrue(direction == "left")
    }

    @Test
    fun jump() {

        eithers.move("north", 10)
            .flatMap { eithers.jump(it, 10) }
            .map { eithers.printDistance(it) }.map { assertTrue(it == "I have jumped 20") }

        eithers.move("north", 10)
            .flatMap { eithers.jump(it, -20) }
            .map { eithers.printDistance(it) }.mapLeft {
                assertTrue { it.message == "going backwards" }
            }
    }
}
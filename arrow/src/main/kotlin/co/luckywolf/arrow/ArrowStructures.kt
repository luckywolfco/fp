package co.luckywolf.arrow

import arrow.core.Either

object EitherStructures {

    data class Left(val left: String = "left")
    data class Right(val right: String = "right")

    fun left() = Either.Left("left")
    fun right() = Either.Right("right")

    fun rightOrLeft(right: Boolean): Either<Left, Right> {
        return if (right)
            Either.Right(Right())
        else
            Either.Left(Left())
    }

    fun move(direction: String, steps: Int): Either<Exception, Int> =
        if (direction == "north" || direction == "south") {
            Either.Right(steps)
        } else Either.Left(Exception("lost"))

    fun jump(steps: Int, jump: Int): Either<Exception, Int> {
        return if (steps + jump < 0)
            Either.Left(Exception("going backwards"))
        else Either.Right(steps + jump)
    }

    fun printDistance(steps: Int): String = "I have jumped $steps"
}
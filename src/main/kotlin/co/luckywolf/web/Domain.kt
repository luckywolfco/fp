package co.luckywolf.web

import akka.actor.typed.*
import akka.actor.typed.javadsl.AskPattern
import akka.actor.typed.javadsl.Behaviors
import java.time.Duration
import java.util.concurrent.CompletionStage


class Main {

    companion object {
        fun create(): Behavior<SpawnProtocol.Command> = Behaviors.setup { SpawnProtocol.create() }
    }
}


class MessageStream(name: String) {
    //context: ActorContext<StreamCommand>) {

    val stream = Stream(name)

    interface StreamCommand
    class JoinUser(val user: String) : StreamCommand
    class LeaveUser(val user: String) : StreamCommand
    class Shutdown(val user: String) : StreamCommand
    class Open(val stream: String) : StreamCommand
    class Start(val stream: String) : StreamCommand
    class PrintUser : StreamCommand

    companion object {
        fun create(name: String): Behavior<StreamCommand> = Behaviors.setup {
            MessageStream(name).behavior()
        }
    }

    fun behavior(): Behavior<StreamCommand> {
        return Behaviors.receive(StreamCommand::class.java)
            .onMessage(JoinUser::class.java, ::onJoinUser)
            .onMessage(LeaveUser::class.java, ::onLeaveUser)
            .onMessage(Shutdown::class.java, ::onShutdown)
            .onMessage(PrintUser::class.java, ::onPrint)
            .build()
    }


    fun onPrint(message: PrintUser): Behavior<StreamCommand> {
        stream.users.forEach { println("user - $it") }
        return Behaviors.same();
    }

    fun onLeaveUser(message: LeaveUser): Behavior<StreamCommand> {
        stream.leave(message.user)
        return Behaviors.same();
    }

    fun onJoinUser(message: JoinUser): Behavior<StreamCommand> {
        println("Joining user ${message.user} to stream ${stream.stream}")
        stream.join(message.user)
        return Behaviors.same();
    }

    fun onShutdown(message: Shutdown): Behavior<StreamCommand> {
        println("Shutting down ${stream.stream}")
        return Behaviors.stopped();
    }
}

data class Stream(val stream: String) {

    val users = mutableSetOf<String>()

    fun join(user: String) {
        users.add(user)
    }

    fun leave(user: String) {
        users.remove(user)
    }
}

fun spawnConnectionActor(
    system: ActorSystem<SpawnProtocol.Command>,
    name: String
): CompletionStage<ActorRef<MessageStream.StreamCommand>> {

    // Asks the [system] actor to spawn a new stream actor
    return AskPattern.ask(
        system,
        { replyTo: ActorRef<ActorRef<MessageStream.StreamCommand>> ->
            SpawnProtocol.Spawn(
                MessageStream.create(name),
                name,
                Props.empty(),
                // Sends the spawned actor's ref to the actor that [replyTo] references
                replyTo
            )
        },
        Duration.ofSeconds(5),
        system.scheduler()

    ).whenComplete { actorRef, exception ->
        if (exception == null) {
            //actors[name] = ref
            //system.log().info("actors $actors")
        }
    }
}





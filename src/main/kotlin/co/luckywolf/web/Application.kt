package co.luckywolf.web


import akka.actor.typed.ActorRef
import akka.actor.typed.ActorSystem
import io.ktor.application.*
import io.ktor.http.cio.websocket.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.testing.*
import io.ktor.websocket.*
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger


fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        httpModule()
        akkaModule()
    }.start(wait = true)
}

fun Application.sockets() {
    akkaModule()
}

class SocketConnection(val session: DefaultWebSocketSession) {
    companion object {
        var lastId = AtomicInteger(0)
    }

    val name = "user_${lastId.getAndIncrement()}"
}


fun Application.akkaModule() {

    install(WebSockets) {
        pingPeriod = Duration.ofSeconds(15)
        timeout = Duration.ofSeconds(15)
        maxFrameSize = Long.MAX_VALUE
        masking = false
    }

    val system = ActorSystem.create(Main.create(), "streams")

    routing {

        val connections = Collections.synchronizedSet<SocketConnection>(LinkedHashSet())
        val actors = ConcurrentHashMap<String, ActorRef<MessageStream.StreamCommand>>()

        webSocket("/ws") {

            val connection = SocketConnection(this)
            connections += connection

            //spawn an actor to represent the connection
            spawnConnectionActor(system, connection.name)
                .whenComplete { actorRef: ActorRef<MessageStream.StreamCommand>, exception ->
                    if (exception == null) {
                        actors[connection.name] = actorRef
                        println("actor connection opened - ${connection.name}")
                    }
                }

            try {

                connection.session.send("actor ready")

                for (frame in incoming) {
                    frame as? Frame.Text ?: continue
                    val receivedText = frame.readText()
                    if(receivedText == "join") {
                        actors[connection.name]?.tell(MessageStream.JoinUser("john "+Random().nextInt(100)))
                    }
                    if(receivedText == "print") {
                        println("printing")
                        actors[connection.name]?.tell(MessageStream.PrintUser())
                    }
                }


            } finally {
                actors[connection.name]?.tell(MessageStream.Shutdown(connection.name))
                connections -= connection
            }
        }
    }
}


fun Application.httpModule() {
    routing {
        get("/") {
            call.respondText("Boom")
        }
    }
}


class ModuleTest {
    @Test
    fun testConversation() {
        withTestApplication(Application::sockets) {
            handleWebSocketConversation("/ws") { incoming, outgoing ->

                outgoing.send(Frame.Text("join"))
                outgoing.send(Frame.Text("join"))
                outgoing.send(Frame.Text("join"))
                outgoing.send(Frame.Text("print"))
                outgoing.send(Frame.Text("join"))

                val closeReason = (incoming.receive() as Frame.Text).readText()
                println(closeReason)

            }
        }
    }
}
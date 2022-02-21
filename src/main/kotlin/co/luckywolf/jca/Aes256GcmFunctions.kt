package co.luckywolf.jca

import arrow.core.*
import co.luckywolf.jca.Aes256GcmFunctions.bouncy
import co.luckywolf.jca.Aes256GcmFunctions.decrypt
import co.luckywolf.jca.Aes256GcmFunctions.decryptionCipher
import co.luckywolf.jca.Aes256GcmFunctions.encrypt
import co.luckywolf.jca.Aes256GcmFunctions.encryptionCipher
import co.luckywolf.jca.Aes256GcmFunctions.gcmAlgorithm
import co.luckywolf.jca.Aes256GcmFunctions.gcmSpecification
import co.luckywolf.jca.Aes256GcmFunctions.key
import co.luckywolf.jca.Aes256GcmFunctions.nonce
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Test
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import kotlin.test.assertEquals

typealias Func<A, B> = (A) -> B


object Aes256GcmFunctions {

    sealed class JcaError(message: String) {
        class UnknownProvider(message: String) : JcaError("Unknown provider - $message")
        class EncryptionError(message: String) : JcaError("Encryption error - $message")
    }

    fun isProvider(provider: String): Option<Provider> {
        val prv = Security.getProvider(provider)
        return when {
            prv != null -> Some(prv)
            else -> none()
        }
    }

    fun bouncy(): Provider {
        val provider = isProvider("BC")
        return provider.getOrElse {
            val bouncy = BouncyCastleProvider()
            Security.addProvider(bouncy)
            bouncy
        }
    }

    fun key(provider: Provider, keysize: Int = 256): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES", provider)
        keyGenerator.init(keysize, SecureRandom())
        return keyGenerator.generateKey()
    }

    fun gcmSpecification(nonce: IvParameterSpec): AlgorithmParameterSpec =
        GCMParameterSpec(128, nonce.iv)

    fun encryptionCipher(
        provider: Provider,
        algo: String,
        secretKey: SecretKey,
        algoSpec: AlgorithmParameterSpec
    ): Cipher {
        val cipher = Cipher.getInstance(algo, provider)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algoSpec)
        return cipher
    }

    fun decryptionCipher(
        provider: Provider,
        algo: String,
        secretKey: SecretKey,
        algoSpec: AlgorithmParameterSpec
    ): Cipher {
        val cipher = Cipher.getInstance(algo, provider)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algoSpec)
        return cipher
    }

    fun gcmAlgorithm() = "AES/GCM/NoPadding"

    fun encrypt(
        plainText: ByteArray,
        cipher: Cipher,
    ): Either<JcaError,ByteArray> {
        return kotlin.runCatching {
            Either.Right(cipher.doFinal(plainText))
        }.getOrElse {
            Either.Left(JcaError.EncryptionError(it.message.orEmpty()))
        }
    }

    fun decrypt(
        encryptedText: ByteArray,
        cipher: Cipher,
    ): Either<JcaError,ByteArray> {
        return kotlin.runCatching {
            Either.Right(cipher.doFinal(encryptedText))
        }.getOrElse {
            Either.Left(JcaError.EncryptionError(it.message.orEmpty()))
        }
    }


    fun nonce(size: Int = 16): IvParameterSpec {
        val nonce = ByteArray(size)
        SecureRandom().nextBytes(nonce)
        return IvParameterSpec(nonce)
    }

    fun key(provider: () -> Provider, keysize: Int = 256): Func<Provider, SecretKey> {
        val keyGenerator = KeyGenerator.getInstance("AES", provider())
        keyGenerator.init(keysize, SecureRandom())
        return { keyGenerator.generateKey() }
    }

    val printProvider: Func<Provider, String> = fun(provider: Provider) = "Provider is $provider"
}

class GcmTests {

    @Test
    fun encrypt_it() {

        val key: (Provider) -> SecretKey = key({ bouncy() }, 256)

        val nonce = nonce()
        val secret = key(bouncy())

        val cipher =
            encryptionCipher(
                bouncy(),
                gcmAlgorithm(),
                secret,
                gcmSpecification(nonce)
            )

        val encrypted = encrypt(
            "plain jane".toByteArray(),
            cipher
        )

        encrypted.map {
            decrypt(
                it,
                decryptionCipher(
                    bouncy(),
                    gcmAlgorithm(),
                    secret,
                    gcmSpecification(nonce)
                )
            ).map {
                assertEquals("plain jane",String(it));
            }
        }
    }
}
package co.luckywolf.jca

import arrow.core.*
import co.luckywolf.jca.Aes256GcmFunctionsFP.bouncy
import co.luckywolf.jca.Aes256GcmFunctionsFP.decrypt
import co.luckywolf.jca.Aes256GcmFunctionsFP.decryptionCipher
import co.luckywolf.jca.Aes256GcmFunctionsFP.encrypt
import co.luckywolf.jca.Aes256GcmFunctionsFP.encryptionCipher
import co.luckywolf.jca.Aes256GcmFunctionsFP.gcmAlgorithm
import co.luckywolf.jca.Aes256GcmFunctionsFP.gcmSpecification
import co.luckywolf.jca.Aes256GcmFunctionsFP.key
import co.luckywolf.jca.Aes256GcmFunctionsFP.nonce
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
import arrow.core.flatMap as fm


object Aes256GcmFunctionsFP {

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

    fun bouncy(): Either<JcaError, Provider> {
        val provider = isProvider("BC").getOrElse {
            val bouncy = BouncyCastleProvider()
            Security.addProvider(bouncy)
            bouncy
        }
        return Either.Right(provider)
    }

    fun key(provider: Provider, keysize: Int = 256): Either<JcaError, SecretKey> {
        val keyGenerator = KeyGenerator.getInstance("AES", provider)
        keyGenerator.init(keysize, SecureRandom())
        return Either.Right(keyGenerator.generateKey())
    }

    fun gcmSpecification(nonce: IvParameterSpec): AlgorithmParameterSpec =
        GCMParameterSpec(128, nonce.iv)

    fun encryptionCipher(
        provider: Provider,
        algo: String,
        secretKey: SecretKey,
        algoSpec: AlgorithmParameterSpec
    ): Either<JcaError, Cipher> {
        val cipher = Cipher.getInstance(algo, provider)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algoSpec)
        return Either.Right(cipher)
    }

    fun decryptionCipher(
        provider: Provider,
        algo: String,
        secretKey: SecretKey,
        algoSpec: AlgorithmParameterSpec
    ): Either<JcaError, Cipher> {
        val cipher = Cipher.getInstance(algo, provider)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, algoSpec)
        return Either.Right(cipher)
    }

    fun gcmAlgorithm() = "AES/GCM/NoPadding"

    fun encrypt(
        plainText: ByteArray,
        cipher: Cipher,
    ): Either<JcaError, ByteArray> =
        Either.Right(cipher.doFinal(plainText))


    fun decrypt(
        encryptedText: ByteArray,
        cipher: Cipher,
    ): Either<JcaError, ByteArray> {
        return Either.Right(cipher.doFinal(encryptedText))
    }


    fun nonce(size: Int = 16): Either<JcaError, IvParameterSpec> {
        val nonce = ByteArray(size)
        SecureRandom().nextBytes(nonce)
        return Either.Right(IvParameterSpec(nonce))
    }

    fun key(provider: () -> Provider, keysize: Int = 256): Func<Provider, SecretKey> {
        val keyGenerator = KeyGenerator.getInstance("AES", provider())
        keyGenerator.init(keysize, SecureRandom())
        return { keyGenerator.generateKey() }
    }

    val printProvider: Func<Provider, String> = fun(provider: Provider) = "Provider is $provider"
}

class Encryption(val key: SecretKey, val nonce: IvParameterSpec, val encryptedText: ByteArray)

class GcmEitherTests {

    @Test
    fun encrypt_it() {

        val encrypted = bouncy().fm { p ->
            key(p).fm { s ->
                nonce().fm { n ->
                    encryptionCipher(
                        p,
                        gcmAlgorithm(),
                        s,
                        gcmSpecification(n)
                    ).fm { c ->
                        encrypt("jane".toByteArray(), c)
                    }.fm { e ->
                        Either.Right(Encryption(s, n, e))
                    }
                }
            }
        }

        val decrypted = encrypted.fm { e ->
            bouncy().fm { p ->
                decryptionCipher(
                    p,
                    gcmAlgorithm(),
                    e.key,
                    e.nonce
                ).fm { c ->
                    decrypt(e.encryptedText, c)
                }
            }
        }

        assertEquals("jane", decrypted.map { String(it) }.getOrElse { "" })
    }
}
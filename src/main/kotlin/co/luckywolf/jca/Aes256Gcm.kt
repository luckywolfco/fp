package co.luckywolf.jca

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


/*

 As a block cipher, AES always operates on 128-bit (16 byte) blocks of plaintext,
 regardless of the key size.

 The important part is that the key length does not affect the block size but the number
 of repetitions of transformation rounds (128 bit key is 10 cycles, 256 bit is 14)

 Random initialization vector (IV). This is just a fancy word for
 random data that is about the size of one block (128 bit). Think about it like the salt of
 the encryption, that is, an IV can be public, should be random and only used one time.

 Never re-use an IV.

 Encryption does not automatically protect against data modification. GCM is basically CTR mode
 which also calculates an authentication tag sequentially during encryption. This authentication
 tag is then usually appended to the cipher text. Its size is an important security property,
 so it should be at least 128 bit long.

 AES-GCM operates with a 32-bit counter, so unfortunately with the same key,
 nonce (IV) pair you can only safely encrypt ~ 64GB of data (2^39-256 bits).
*/

class Aes256Gcm private constructor(private val provider: Optional<String>) {

    private val ALGORITHM = "AES/GCM/NoPadding"

    //Requires jce unlimited strength policy on JRE
    private val AES_KEY_SIZE = 256

    private val AES_TAG_SIZE = 128

    //recommended NIST
    private val IV_SIZE = 12

    companion object {

        fun cavium(): Aes256Gcm {
            return Aes256Gcm(Optional.of("Cavium"))
        }

        fun sunJCE(): Aes256Gcm {
            return Aes256Gcm(Optional.empty())
        }
    }

    fun generateKey(): SecretKey {
        val keyGen = provider.map { KeyGenerator.getInstance("AES", it) }.orElse(KeyGenerator.getInstance("AES"))
        keyGen.init(AES_KEY_SIZE, SecureRandom())
        return keyGen.generateKey()
    }

    fun zero(b: ByteArray) {
        for (i in b.indices) {
            b[i] = 0
        }
    }

    fun decrypt(
        encryptedText: ByteArray,
        key: ByteArray,
        ivBytes: ByteArray,
        contextInfo: Optional<ByteArray> = Optional.empty()
    ): ByteArray {

        if (key.size < 32) {
            throw IllegalArgumentException("Key length must be 32 bytes")
        }

        if (ivBytes.size != 12 && ivBytes.size != 16) {
            throw IllegalStateException("Unexpected iv length")
        }

        val cipher = provider.map { Cipher.getInstance(ALGORITHM, it) }.orElse(Cipher.getInstance(ALGORITHM))
        val keySpec = SecretKeySpec(key, "AES")
        val gcmParameterSpec = GCMParameterSpec(AES_TAG_SIZE, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec)

        contextInfo.map {
            cipher.updateAAD(it)
        }

        return cipher.doFinal(encryptedText)
    }

    fun decrypt(
        encryptedText: ByteArray,
        key: ByteArray,
        contextInfo: Optional<ByteArray> = Optional.empty()
    ): ByteArray {

        if (key.size < 32) {
            throw IllegalArgumentException("Key length must be 32 bytes")
        }

        val cipher = provider.map { Cipher.getInstance(ALGORITHM, it) }.orElse(Cipher.getInstance(ALGORITHM))

        val bb = ByteBuffer.wrap(encryptedText)

        val encrypted = ByteArray(encryptedText.size - IV_SIZE)
        bb.get(encrypted);

        val iv = ByteArray(bb.remaining())
        bb.get(iv)

        val gcmParameterSpec = GCMParameterSpec(AES_TAG_SIZE, iv)
        val keySpec = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec)

        contextInfo.map {
            cipher.updateAAD(it)
        }

        return cipher.doFinal(encrypted)
    }

    fun encrypt(
        plainText: ByteArray,
        key: ByteArray,
        contextInfo: Optional<ByteArray> = Optional.empty()
    ): EncryptedData {

        if (key.size < 32) {
            throw IllegalArgumentException("Key length must be 32 bytes")
        }

        val cipher = provider.map { Cipher.getInstance(ALGORITHM, it) }.orElse(Cipher.getInstance(ALGORITHM))

        val aesKey = SecretKeySpec(key, "AES")
        val ivBytes = nonce()
        val iv = GCMParameterSpec(AES_TAG_SIZE, ivBytes)

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv)

        contextInfo.map {
            cipher.updateAAD(it)
        }

        val encrypted = cipher.doFinal(plainText)

        val combined = ByteBuffer.allocate(encrypted.size + IV_SIZE)
            .put(encrypted)
            .put(ivBytes)
            .array()

        return EncryptedData(
            provider.orElse("sunJCE"),
            "AES_256_GCM",
            key,
            plainText,
            encrypted,
            ivBytes,
            combined
        )

    }

    fun encrypt(plainText: ByteArray, contextInfo: Optional<ByteArray> = Optional.empty()): EncryptedData {

        val cipher = provider.map { Cipher.getInstance(ALGORITHM, it) }.orElse(Cipher.getInstance(ALGORITHM))

        val keygen = provider.map { KeyGenerator.getInstance("AES", it) }.orElse(KeyGenerator.getInstance("AES"))

        keygen.init(AES_KEY_SIZE)
        val aesKey = keygen.generateKey()
        val ivBytes = nonce()
        val gcmParameterSpec = GCMParameterSpec(AES_TAG_SIZE, ivBytes)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec)

        contextInfo.map {
            cipher.updateAAD(it)
        }
        val encrypted = cipher.doFinal(plainText)

        val combined = ByteBuffer.allocate(encrypted.size + IV_SIZE)
            .put(encrypted)
            .put(ivBytes)
            .array()

        return EncryptedData(
            provider.orElse("sunJCE"),
            "AES_256_GCM",
            aesKey.encoded,
            plainText,
            encrypted,
            ivBytes,
            combined
        )
    }


    private fun nonce(): ByteArray {
        val nonce = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(nonce)
        return nonce
    }


}

class EncryptedData(
    val provider: String,
    val algorithm: String,
    val key: ByteArray,
    val plainText: ByteArray,
    val encryptedText: ByteArray,
    val nonce: ByteArray,
    val combinedNonceEncryptedText: ByteArray
)
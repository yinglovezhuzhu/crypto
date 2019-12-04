package com.owen.crypto.rsa


import com.owen.crypto.CryptoUtils
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher


/**
 *
 * <br/>Author：yunying.zhang
 * <br/>Email: yunyingzhang@rastar.com
 * <br/>Date: 2019/11/26
 */


//The padding margin is as follows:
//
//RSA/ECB/PKCS1Padding, 11
//RSA/ECB/NoPadding, 0
//RSA/ECB/OAEPPadding, 42 // Actually it's OAEPWithSHA1AndMGF1Padding
//RSA/ECB/OAEPWithMD5AndMGF1Padding, 34
//RSA/ECB/OAEPWithSHA1AndMGF1Padding, 42
//RSA/ECB/OAEPWithSHA224AndMGF1Padding, 58
//RSA/ECB/OAEPWithSHA256AndMGF1Padding, 66
//RSA/ECB/OAEPWithSHA384AndMGF1Padding, 98
//RSA/ECB/OAEPWithSHA512AndMGF1Padding, 130
//RSA/ECB/OAEPWithSHA3-224AndMGF1Padding, 58
//RSA/ECB/OAEPWithSHA3-256AndMGF1Padding, 66
//RSA/ECB/OAEPWithSHA3-384AndMGF1Padding, 98
//RSA/ECB/OAEPWithSHA3-512AndMGF1Padding, 130
const val RSA_ALGORITHM: String = "RSA/ECB/PKCS1Padding"

class RSAHelper(var publicKey: PublicKey, var privateKey: PrivateKey, var keySize: Int) {

    fun publicEncrypt(data: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return splitCodec(cipher, Cipher.ENCRYPT_MODE, data, keySize)
    }

    fun publicDecrypt(data: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, publicKey)
        return splitCodec(cipher, Cipher.DECRYPT_MODE, data, keySize)
    }

    fun privateEncrypt(data: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)
        return splitCodec(cipher, Cipher.ENCRYPT_MODE, data, keySize)
    }

    fun privateDecrypt(data: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return splitCodec(cipher, Cipher.DECRYPT_MODE, data, keySize)
    }

    private fun splitCodec(cipher: Cipher, opmode: Int, data: ByteArray, keySize: Int ): ByteArray? {
        val maxBlockSize = if (opmode == Cipher.DECRYPT_MODE) {
            keySize / 8
        } else {
            keySize / 8 - 11
        }
        val out = ByteArrayOutputStream()
        var offSet = 0
        var buff: ByteArray
        var blockSize: Int
        try {
            while (offSet < data.size) {
                blockSize = if (data.size - offSet > maxBlockSize) {
                     maxBlockSize
                } else {
                    data.size - offSet
                }
                buff = cipher.doFinal(data, offSet, blockSize)
                out.write(buff, 0, buff.size)
                offSet += blockSize
            }
            return out.toByteArray()
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            out.close()
        }
        return null
    }


    companion object {

        /**
         * 解析Base64编码的公钥
         * @param publicKey Base64编码的公钥
         * @return PublicKey
         */
        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun getPublicKeyFromBase64(publicKey: String): PublicKey {
            return getPublicKey(Base64.getDecoder().decode(publicKey))
        }

        /**
         * 解析Base64编码的私钥
         * @param privateKey Base64编码的公钥
         * @return PublicKey
         */
        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun getPrivateKeyFromBase64(privateKey: String): PrivateKey {
            return getPrivateKey(Base64.getDecoder().decode(privateKey))
        }

        /**
         * 得到公钥
         * @param publicKey 公钥秘钥
         * @throws Exception
         */
        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun getPublicKey(publicKey: ByteArray): PublicKey { //通过X509编码的Key指令获得公钥对象
            val keyFactory = KeyFactory.getInstance(RSA_ALGORITHM)
            val x509KeySpec = X509EncodedKeySpec(publicKey)
            return keyFactory.generatePublic(x509KeySpec)
        }

        /**
         * 得到私钥
         * @param privateKey 私钥秘钥
         * @throws Exception
         */
        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun getPrivateKey(privateKey: ByteArray): PrivateKey { //通过PKCS#8编码的Key指令获得私钥对象
            val keyFactory = KeyFactory.getInstance(RSA_ALGORITHM)
            val pkcs8KeySpec = PKCS8EncodedKeySpec(privateKey)
            return keyFactory.generatePrivate(pkcs8KeySpec)
        }

    }
}


fun main(args: Array<String>) {

    val keyPair = CryptoUtils.generateKeyPair("RSA", 1024)

    println(Base64.getEncoder().encodeToString(keyPair.public.encoded))
    println(Base64.getEncoder().encodeToString(keyPair.private.encoded))

    val rsa = RSAHelper(keyPair.public, keyPair.private, 1024)

    val s = "Hello, Kotlin"

    val en = rsa.privateEncrypt(s.toByteArray())


    if(null != en) {
        val dn = rsa.publicDecrypt(en)
        if(null != dn) println(String(dn))
    }
}
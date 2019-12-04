package com.owen.crypto.aes

import com.owen.crypto.CryptoUtils
import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES加解密
 * <br/>Author：owen
 * <br/>Email: zhangyy_owen@139.com
 * <br/>Date: 2019/11/20
 */
class AESHelper(keySpec: ByteArray, ivParameterSpec: ByteArray? = null, trans: String? = "AES/CFB/NoPadding") {

    private val secretKeySpec: SecretKeySpec = SecretKeySpec(keySpec, "AES")
    private val parameterSpec: IvParameterSpec = IvParameterSpec(ivParameterSpec ?: com.owen.crypto.md5.encrypt(keySpec))
    private val transformation = trans

    /**
     * 解密
     *
     * @param data 加密二进制数据
     * @return 加密后二进制数据
     */
    fun encrypt(data: ByteArray): ByteArray? {
        var result: ByteArray? = null

        try {
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec)
            result = cipher.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        }
        return result
    }

    /**
     * 解密
     * @param data 需要解密的二进制数据
     * @return 解密后的二进制数据
     */
    fun decrypt(data: ByteArray): ByteArray? {
        var result: ByteArray? = null

        try {
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec)
            result = cipher.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        }
        return result
    }

}




fun main(args: Array<String>): Unit {

    val str = "Hello, Kotlin"

    val key = CryptoUtils.generateKey("AES")
    val aesHelper = AESHelper(key.encoded)
    val encrypted = aesHelper.encrypt(str.toByteArray())
    if(null != encrypted) {
        val decrypted = aesHelper.decrypt(encrypted)
        if(null != decrypted) {
            println(String(decrypted))
        }
    }


    val s = " 螺 旋の力バッグII "
    println(s)
    println(s.trim())

}
package com.owen.crypto.md5

import com.owen.crypto.CryptoUtils
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.security.DigestInputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * MD5工具类
 * <br/>Author：owen
 * <br/>Email: zhangyy_owen@139.com
 * <br/>Date: 2019/11/20
 */

fun main(args: Array<String>) {

    println(encryptFile(File("E:\\RastarGameSDK\\cn\\rastar_msdk_library\\libs_sanwan\\libs\\SanWanSDK.jar")))

}


/**
 * 计算字符串MD5
 * @param str 需要计算MD5的字符串
 * @return 字符串十六进制MD5（大写）
 */
fun encryptString(str: String): String  = CryptoUtils.bytes2HexString(encrypt(str))


/**
 * 计算文件MD5
 *
 * @param file 计算MD5的文件
 * @return 文件的16进制MD5值（大写）
 */
fun encryptFile(file: File): String = CryptoUtils.bytes2HexString(encrypt(file))


/**
 * MD5加密文件
 *
 * @param file 文件
 * @return 文件的MD5校验码
 */
fun encrypt(file: File): ByteArray? {
    var fis: FileInputStream? = null
    var digestInputStream: DigestInputStream? = null
    try {
        fis = FileInputStream(file)
        var md = MessageDigest.getInstance("MD5")
        digestInputStream = DigestInputStream(fis, md)
        val buffer = ByteArray(256 * 1024)
        while (true) {
            if (digestInputStream.read(buffer) <= 0) break
        }
        md = digestInputStream.messageDigest
        return md.digest()
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
        return null
    } catch (e: IOException) {
        e.printStackTrace()
        return null
    } finally {
        digestInputStream?.close()
        fis?.close()
    }
}

/**
 * 计算MD5值
 * @param str 计算MD5的字符串
 * @return MD5值二进制数组
 */
fun encrypt(str: String): ByteArray? {
    if (str.isEmpty()) return null
    return try {
        val md5 = MessageDigest.getInstance("MD5")
        md5.digest(str.toByteArray())
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
        null
    }
}

/**
 * 计算MD5值
 * @param data 计算MD5的二进制数组
 * @return MD5值二进制数组
 */
fun encrypt(data: ByteArray): ByteArray? {
    if(data.isEmpty()) {
        return null
    }
    return try {
        val md5 = MessageDigest.getInstance("MD5")
        md5.digest(data)
    } catch (e: NoSuchAlgorithmException) {
        e.printStackTrace()
        null
    }
}


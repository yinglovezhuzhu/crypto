package com.owen.crypto

import java.security.InvalidParameterException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


/**
 *
 * <br/>Author：owen
 * <br/>Email: zhangyy_owen@139.com
 * <br/>Date: 2019/11/20
 */

class CryptoUtils {
    companion object {
        private val hexDigits = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')

        /**
         * byteArr转hexString
         *
         * 例如：
         * bytes2HexString(new byte[] { 0, (byte) 0xa8 }) returns 00A8
         *
         * @param bytes 字节数组
         * @return 16进制大写字符串
         */
        fun bytes2HexString(bytes: ByteArray?): String {
            if (null == bytes || bytes.isEmpty()) return ""
            val len = bytes.size
            val ret = CharArray(len shl 1) // 按位左移一位，相当于x2
            var j = 0
            for (i in 0 until len) {
                // 四位二进制表示无符号范围是0~15
                ret[j++] = hexDigits[bytes[i].toInt().ushr(4) and 0x0f] // 无符号右移4位与0x0f，取高4位
                ret[j++] = hexDigits[bytes[i].toInt() and 0x0f] // 按位与0x0f，取低四位
            }
            return String(ret)
        }

        /**
         * 生成一个简单的秘钥
         * @param algorithm 秘钥类型
         * @param keySize 秘钥长度
         *
         * @return 秘钥
         */
        fun generateKey(algorithm: String, keySize: Int = 128): SecretKey {
            val keyGenerator = KeyGenerator.getInstance(algorithm)
            keyGenerator.init(keySize)
            return keyGenerator.generateKey()
        }


        @Throws(NoSuchAlgorithmException::class, InvalidParameterException::class)
        fun generateKeyPair(algorithm: String, keySize: Int): KeyPair {
            val keyGenerator = KeyPairGenerator.getInstance(algorithm)
            keyGenerator.initialize(keySize)
            return keyGenerator.generateKeyPair()
        }
    }

}
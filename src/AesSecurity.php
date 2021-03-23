<?php
namespace draco\security;

/**
 * [AesSecurity aes加密，支持PHP7.1]
 * ECB加密模式（不推荐）
 * 算法特点：
 * 1. 每次Key、明文、密文长度都必须是64位
 * 2. 数据块重复排序不需要检测
 * 3. 相同的明文块（使用相同的密钥）产生相同的密文块，容易遭受字典攻击
 * 4. 一个错误仅仅会对一个密文块产生影响
 *
 * CBC加密模式（推荐）
 * 算法特点：
 * 1. 每次加密的密文长度为64位（8个字节）
 * 2. 当相同的明文使用相同的密钥和初始向量的时候CBC模式总是产生相同的密文
 * 3. 密文块要依赖以前的操作结果，所以，密文块不能进行重新排序
 * 4. 可以使用不同的初始向量来避免相同的明文产生相同的密文，一定程度上抵抗字典攻击
 * 5. 一个错误发生后，当前和以后的密文都会被影响
 */
class AesSecurity
{
    const AES_CBC_128 = 'AES-128-CBC';
    const AES_CBC_256 = 'AES-256-CBC';
    const AES_ECB_128 = 'AES-128-ECB';
    const AES_ECB_256 = 'AES-256-ECB';

    private static  $key; // 加密key
    private static $iv; // IV初始向量16位
    private static $cipher; // 加解密的向量

    /**
     * AesSecurity constructor.
     * @param $key [加密key]
     * @param string $iv [加解密的向量]
     * @param string $cipher [加密解密类型, 可通过openssl_get_cipher_methods()获得]
     */
    public function __construct($key, $iv = '', $cipher = '')
    {
        static::$key    = $key;
        static::$iv     = empty($cipher) ? '' : $iv;
        static::$cipher = empty($cipher) ? static::AES_ECB_128 : $cipher;
    }

    /**
     * [encrypt aes加密]
     * @param string $input [要加密的数据]
     * @return   string [加密后的数据]
     */
    public function encrypt($input)
    {
        $data = openssl_encrypt($input, static::$cipher, static::$key, OPENSSL_RAW_DATA, static::$iv);
        $data = base64_encode($data);
        return $data;
    }
    /**
     * [decrypt aes解密]
     * @param    string $input [要解密的数据]
     * @return   string [解密后的数据]
     */
    public function decrypt($input)
    {
        $data = base64_decode($input);
        $data = openssl_decrypt($data, static::$cipher, static::$key, OPENSSL_RAW_DATA, static::$iv);
        return $data;
    }
}
<?php
namespace draco\phpseclib;

/**
 * AES加密
 * @package draco\phpseclib
 */
class AesCrypt
{
    // 密钥
    private static $key = '';
    // 偏移量(ECB模式不需要)
    private static $iv = '';
    // 加密模式
    private static $cipher = 'AES-128-ECB';
    // 返回指定编码的字符串
    private static $character = 'base64';

    /**
     * 析构函数
     * @param string $key
     * @param string $iv
     * @param string $cipher
     */
    public function __construct(string $key = '', string $iv = '', string $cipher = '')
    {
        $key && static::$key = $key;
        $iv && static::$iv = $iv;
        $cipher && static::$cipher = $cipher;
    }

    /**
     * 加密
     * @author: draco 2021/5/11 11:06
     * @param string $input
     * @return string
     */
    public function encrypt(string $input = ''): string
    {
        $data = openssl_encrypt($input, static::$cipher, static::$key, OPENSSL_RAW_DATA, static::$iv);

        switch (static::$character) {
            case 'base64':
                $data = base64_encode($data);
                break;
            case 'hex':
                $data = bin2hex($data);
                break;
        }

        return $data;
    }

    /**
     * 解密
     * @author: draco 2021/5/11 11:07
     * @param string $input
     * @return string
     */
    public function decrypt(string $input = ''): string
    {
        $data = '';
        switch (static::$character) {
            case 'base64':
                $data = base64_decode($input);
                break;
            case 'hex':
                $data = hex2bin($input);
                break;
        }

        return openssl_decrypt($data, static::$cipher, static::$key, OPENSSL_RAW_DATA, static::$iv);
    }

    /**
     * 设置返回字符串指定编码
     * @author: draco 2021/5/11 11:07
     * @param string $character
     */
    public function setCharacter($character = '')
    {
        $characterArr = [
            'base64',
            'hex',
        ];
        if (in_array($character, $characterArr)) {
            static::$character = $character;
        }
    }

    /**
     * 设置加密模式
     * @author: draco 2021/5/11 11:08
     * @param $cipher
     */
    public function setCipher($cipher)
    {
        $cipher && static::$cipher = $cipher;
    }

    /**
     * 获取所有加密模式
     * @author: draco 2021/5/11 11:09
     * @return array
     */
    public function getAllCipher(): array
    {
        $result = [];
        $ciphers = openssl_get_cipher_methods();

        foreach ($ciphers as $cipher) {
            if (strpos($cipher, 'aes-') !== false) {
                $result[] = $cipher;
            }
        }

        return $result;
    }
}
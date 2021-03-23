<?php
namespace draco\security;

/**
 * des加密解密
 * Class DesSecurity
 * @package draco\security
 */
class DesSecurity
{
    private static $key;
    public function  __construct($key) {
        static::$key = $key;
    }

    /**
     * 加密
     * @param $input
     * @return string 转换后的字符串
     */
    public function encrypt($input)
    {
        $size = mcrypt_get_block_size('des', 'ecb');
        $input = $this->pkcs5_pad($input, $size);
        $td = mcrypt_module_open('des', '', 'ecb', '');
        $iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        @mcrypt_generic_init($td, static::$key, $iv);
        $data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        $data = $this->byteArr2HexStr($this->getBytes($data));
        return $data;
    }

    /**
     * 解密
     * @param $encrypted
     * @return false|string
     */
    public function decrypt($encrypted)
    {
        $encrypted = $this->array2str($this->hexStr2ByteArr($encrypted));
        $td = mcrypt_module_open('des','','ecb','');
        //使用MCRYPT_DES算法,cbc模式
        $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        $ks = mcrypt_enc_get_key_size($td);
        @mcrypt_generic_init($td, static::$key, $iv);
        //初始处理
        $decrypted = mdecrypt_generic($td, $encrypted);
        //解密
        mcrypt_generic_deinit($td);
        //结束
        mcrypt_module_close($td);
        return $this->pkcs5_unPad($decrypted);
    }

    private function pkcs5_pad ($text, $blockSize = 0)
    {
        $pad = $blockSize - (strlen($text) % $blockSize);
        return $text . str_repeat(chr($pad), $pad);
    }

    private function pkcs5_unPad($text)
    {
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text))
            return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
            return false;
        return substr($text, 0, -1 * $pad);
    }

    /**
     * 将字符串转换为ASCII码值数组，和array2str 互为可逆的转换过程
     *
     * @param string $string 需要转换的字符串
     * @return array 转换后的ASCII码值数组
     */
    private function getBytes($string)
    {
        $bytes = array();
        for($i = 0; $i < strlen($string); $i++){
            $bytes[] = ord($string[$i]);
        }
        return $bytes;
    }

    /**
     * 将ASCII码值数组转换为字符串，和getBytes 互为可逆的转换过程
     *
     * @param array $array 需要转换的ASCII码值数组
     * @return string 转换后的字符串
     */
    private function array2str($array)
    {
        $string = '';
        foreach ($array as $key => $value) {
            $string .= chr($value);
        }
        return $string;
    }

    /**
     * 将数组转换为表示16进制值的字符串，和hexStr2ByteArr(String strIn) 互为可逆的转换过程
     *
     *
     * @param array 需要转换的byte数组
     * @return string 转换后的字符串
     */
    private function byteArr2HexStr($array)
    {
        $iLen = count($array);
        $return_str = '';
        for ($i = 0; $i < $iLen; $i++)
        {
            $intTmp = $array[$i];
            // 把负数转换为正数
            while ($intTmp < 0) {
                $intTmp = $intTmp + 256;
            }

            $intTmp = dechex($intTmp);
            // 小于0F的数需要在前面补0
            if(hexdec($intTmp) < 16)
            {
                $intTmp = '0' . $intTmp;
            }
            $return_str =  $return_str . $intTmp;
        }

        return $return_str;
    }

    /**
     * 将表示16进制值的字符串转换为数组， 和byteArr2HexStr互为可逆的转换过程
     *
     * @param string $string 需要转换的字符串
     * @return array 转换后的数组
     */
    private function hexStr2ByteArr($string)
    {
        $len = strlen($string);

        $return = array();
        for($i=0;$i<$len;$i=$i+2)
        {
            $return[] = hexdec(substr($string,$i,2));
        }

        return $return;
    }
}
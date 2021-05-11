<?php
require_once '../vendor/autoload.php';

$aesCrypt = new draco\phpseclib\AesCrypt('PasswordPassword', 'dynamic@dynamic@');
// $aesCrypt->setCharacter('hex');
// var_dump($aesCrypt->getAllCipher());
$aesCrypt->setCipher('AES-128-CBC');
$input = 'Hello';
$result = $aesCrypt->encrypt($input);
var_dump($result);

$result = $aesCrypt->decrypt($result);
var_dump($result);

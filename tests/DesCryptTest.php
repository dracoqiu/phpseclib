<?php
require_once '../vendor/autoload.php';

$desCrypt = new draco\phpseclib\DesCrypt('PasswordPassword', 'dynamic@dynamic@');
// $desCrypt->setCharacter('hex');
// var_dump($desCrypt->getAllCipher());
$desCrypt->setCipher('des-ecb');
$input = 'Hello';
$result = $desCrypt->encrypt($input);
var_dump($result);

$result = $desCrypt->decrypt($result);
var_dump($result);

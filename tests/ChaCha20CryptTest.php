<?php
require_once '../vendor/autoload.php';

$desCrypt = new draco\phpseclib\ChaCha20Crypt('PasswordPasswordPasswordPassword', 'dynamic@dyna');
// $desCrypt->setCharacter('hex');
// var_dump($desCrypt->getAllCipher());
$desCrypt->setCipher('chacha20-poly1305');
$input = 'Hello';
$result = $desCrypt->encrypt($input);
var_dump($result);

$result = $desCrypt->decrypt($result);
var_dump($result);

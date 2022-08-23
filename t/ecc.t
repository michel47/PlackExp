#!/usr/bin/perl
#
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use Crypt::PK::ECC qw();
use basic (@basic::EXPORT_OK);

my$curve = 'secp256k1';
my $priv58 = 'ZaW1Nu8ZcFXDsbVmcTEGNHVdQkJeGxzzC5yesWnA5EvFH';
my $pub58 = 'ZZ3QXZd3a6JL2s1en2Kq5SeY9ThU9gzQKG4a2o8eqRsLh';

   my $message = substr khash('SHA256','123 polichinelle'),0,224/8;
   my $cleartext = substr($message."\0"."\xA5"x31,0,32);
   printf "cleartext: %s\n",encode_mbase64($cleartext);
   printf "cleartext: %s\n",encode_mbase16($cleartext);

   my $pub_raw = &decode_mbase58($pub58);
   my $pk = Crypt::PK::ECC->new();
   my $pub = $pk->import_key_raw($pub_raw, $curve);
   printf "ecEncrypt.pub: %s\n",&encode_mbase58($pub->export_key_raw('public_compressed'));
   my $cipher = $pk->encrypt($cleartext, 'SHA256');
   my $cipher64 = encode_mbase64($cipher);
   printf "cipher64: %s\n",$cipher64;

   my $priv_raw = &decode_mbase58($priv58);
   my $sk = Crypt::PK::ECC->new();
   my $priv = $sk->import_key_raw($priv_raw, $curve);
   printf "ecDecrypt.pub: %s\n",&encode_mbase58($priv->export_key_raw('public_compressed'));
   my $ciphertext = decode_mbase64($cipher64);
   my $plaintext = $sk->decrypt($ciphertext);
   printf "plaintext: %s\n",encode_mbase64($plaintext);
   printf "plaintext: %s\n",encode_mbase16($plaintext);

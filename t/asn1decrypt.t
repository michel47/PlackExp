#!/usr/bin/perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
use basic qw(decode_mbase64 encode_mbase58 encode_mbase16 encode_mbase64 decode_mbase58 khash);
use keys qw(DHSecret xorPlain);

my $ASNdef = q<
ECCEncrypt ::= SEQUENCE {
hashID OBJECT IDENTIFIER, -- OID of hash used (default: 2.16.840.1.101.3.4.2.1)
pubkey OCTET STRING , -- Encapsulated ECCPublicKey
skey OCTET STRING -- xor of plaintext and
--"hash of shared secret"
}>;

print "--- # $0\n";
my $tests_run = 1;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {
   use MIME::Base64 qw(decode_base64);
   my $cleartext = &decode_mbase58('ZVFnoYRpeAuhZi44sgHBvTCeSQkEnaD2BVb4DEVQkrrX');
   my $cipher64 = 'mMFAGCWCGSAFlAwQCAQQhAgZJTi/JB0xF6nA1RUGNET6BXo2M5xFdFV8+kDN4ZMQJBCB3G+ZSTFbDuHEN7rtpjuN4+D+0jvrYO2tVNVXzm/L+Og';
   my $cipher_raw = &decode_base64(substr($cipher64,1));

   use Convert::ASN1;
   my $asn = new Convert::ASN1;
   my $ok = $asn->prepare( $ASNdef ); die "*** Could not prepare definition: ".$asn->error() if !$ok;
   my $top = $asn->find('ECCEncrypt'); die "*** Could not find top of structure: ".$asn->error() if !$top;
   my $result = $top->decode($cipher_raw); die "*** Could not decode cipher ".$top->error() if !$result;

   use YAML::XS qw(Dump);
   printf "--- # asn1.decode: %s...\n",Dump($result);
   my $pubkey_raw = $result->{pubkey};
   my $skey_raw = $result->{skey};

   my $pubkey = &encode_mbase58($pubkey_raw);
   printf "pubkey: %s (%sB)\n",$pubkey,length($pubkey_raw);
   printf "skey_raw: %s (%sB)\n",&encode_mbase16($skey_raw),length($skey_raw);

   my $DHb = { &DHSecret($keys::skb,$pubkey) };
   printf "dhsecret: %s\n",$DHb->{secret64};
   my $secret_raw = $DHb->{secret_raw};
   my $dkey = khash('SHA256',$secret_raw);
   my $plain = xorPlain($dkey, $skey_raw); # <- decrypt !
   printf "skey : %s\n",&encode_mbase16($skey_raw);
   printf "dkey : %s\n",&encode_mbase16($dkey);
   printf "plain: %s\n",&encode_mbase16($plain);
   printf "plain: %s\n",&encode_mbase58($plain);

   my $curve = 'secp256k1';
   use Crypt::PK::ECC qw();
   my $sk  = Crypt::PK::ECC->new();
   my $priv = $sk->import_key_raw(&decode_mbase58($keys::skb), $curve);
   my $pk = Crypt::PK::ECC->new();
   my $pub = $priv->export_key_raw('public_compressed');
   my $pkb = &encode_mbase58($pub);
   printf "pkb: %s\n",$pkb;

   my $clear = $priv->decrypt($cipher_raw);
   printf "clear: %s\n",&encode_mbase58($clear);

   is $plain, $clear, "testing manual decryption !";


   if (0) {
      print '-'x64,"\n";
      my $cipher64= keys::ecEncrypt($keys::pkb,$cleartext);
      my $cipher = &decode_mbase64($cipher64);
      printf "cipher16: %s\n",&encode_mbase16($cipher);
      printf "cipher64: %s\n",$cipher64;
      my $plain = keys::ecDecrypt($keys::skb,$cipher64);
      printf "plain: %s\n",&encode_mbase64($plain);
      print '-'x64,"\n";
   }

}

done_testing($tests_run);
print "...\n";
exit $?;

1; # --------------------------------------------------

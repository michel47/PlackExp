#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16 encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite

DUT: {

   my $msg = "Testing Signature";
   my $data = pack('H*','015500').&varint(length($msg)).$msg;
   my $zmh = &encode_mbase58($data);
   my $hash = khash('SHA256',$data,'private key seed');
   my $nonce_raw =substr($hash,16);
   my $nonce = &encode_uuid($nonce_raw);
   printf "nonce: %s\n",$nonce;
   my $pair = { getPrivateKey($nonce,salt => pack'H4',substr(unpack('H*',$hash),-5,4)) };
   #printf "--- # pair %s---\n",Dump($pair);
   my ($sku,$pku) = ($pair->{private}, $pair->{public});

   my $sign = ecSign($sku,"message a signer",'SHA256');
   printf "sign: %s\n",$sign;
   my $verif = ecVerify($pku,$sign,"message a signer",'SHA256');
   printf "verif: %s\n",$verif;

}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;
1;

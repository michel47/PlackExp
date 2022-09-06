#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16 encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite

DUT: {

   my $nonce_raw = random(16);
   my $nonce = &encode_uuid($nonce_raw);
   printf "nonce: %s\n",$nonce;

   my $uuid = getuuid('private key for test');
   printf "uuid: %s\n",$uuid;
   my $pair = { getPrivateKey($uuid,salt => pack'H4',substr(unpack('H*',$uuid),-5,4)) };
   my ($sku,$pku) = ($pair->{private}, $pair->{public});
   printf "sku: %s\n",$sku;


   my $message = "message à signer $nonce";
   printf "message: %s\n",$message;

   my $sign = ecSign($sku,$message,'SHA256');
   printf "sign: %s\n",$sign;
   my $verif = ecVerify($pku,$sign,$message,'SHA256');
   printf "verif: %s\n",$verif;

   is $verif, $sign, "signature verification";

}

done_testing(1);
print "...\n";
# --------------------------------------------------
exit $?;
1;

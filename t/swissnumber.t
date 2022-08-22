#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16 encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {

my $msg = "Testing SwissNumber methods";
my $data = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($data);
my $hash = khash('SHA256',$data,'private key seed');
my $uuid = &encode_uuid(substr($hash,16));

printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$data;
printf "zmh: %s\n",$zmh;
printf "uuid: %s\n",$uuid;
my $pair = { getPrivateKey($uuid,salt => unpack'H4',substr($hash,-3,2)) };
#printf "--- # pair %s---\n",Dump($pair);
my ($sku,$pku) = ($pair->{private}, $pair->{public});
printf "sku: %s\n",$sku;
my $SNobj = { swissnumber($msg,$sku,"message for $pku") };
printf "pku: %s\n",$pku;
my $SNu = { swissnumber($msg,$pku,"message for $pku") };
printf "--- # SNobj %s---\n",Dump($SNobj);
is $SNobj->{value}, $SNu->{value}, "testing swissnumber for $uuid";
   $tests_run++;


}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


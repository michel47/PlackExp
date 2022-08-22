#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16 encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {

my $msg = "Testing UUID methods";
my $data = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($data);
my $hash = khash('SHA256',$data,'private key seed');
my $seed = &encode_uuid(substr($hash,16));

printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$data;
printf "zmh: %s\n",$zmh;
printf "seed: %s\n",$seed;
my $pair = { getPrivateKey($seed,salt => unpack'H4',substr($hash,-3,2)) };
#printf "--- # pair %s---\n",Dump($pair);
my ($sku,$pku) = ($pair->{private}, $pair->{public});
printf "sku: %s\n",$sku;
my $SNu = { swissnumber($pku,$sku,"uuid for $pku") };
printf "uuid: %s\n",$SNu->{uuid};
is $SNu->{uuid}, '92c0e04b-b3f1-1082-e2cf-88ed2059d7bb', "testing uuid for $pku";
   $tests_run++;


}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


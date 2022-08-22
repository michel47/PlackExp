#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16 encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {

my $msg = "Testing finger print methods";
my $data = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($data);
my $b64 = &encode_base64($data);
my $mmh = &encode_mbase64($data);
printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$data;
printf "zmh: %s\n",$zmh;
printf "mmh: %s\n",$mmh;
my $seed = &encode_uuid(substr($data."\x0"x32,0,32));
printf "seed %s\n",$seed;
my $userkey = { getKeyPair($seed,salt => '2309') };
my $sku = $userkey->{private}; printf "sku: %s\n",$sku;
my $pku = $userkey->{public}; printf "pku: %s\n",$pku;
my $pkb = $keys::pkb; printf "pkb: %s\n",$pkb;
my $dhsecret = &DHSecret($sku,$pkb);
printf"dhsecret: %s\n",&encode_mbase64($dhsecret);

my $obj = { fprint($msg,$userkey->{public}) };
printf"--- # footprint: %s---\n",Dump($obj);

is $obj->{fp}, 'f1147ae1-c931-fb5a-e48f-d39a41eab570', "testing fprint for $pku";
   $tests_run++;


}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


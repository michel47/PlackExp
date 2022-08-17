#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint encode_mbase64 encode_mbase58 encode_mbase16);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 3; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {

my $msg = "Testing mnemonic methods";
my $hash = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($hash);
my $mmh = &encode_mbase64($hash);
printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$hash;
printf "zmh: %s\n",$zmh;
printf "mmh: %s\n",$mmh;
my $mnemo = &getMnemonic($mmh);
printf "mnemo: %s\n",$mnemo;
my $entropy = &getEntropy($mnemo);
printf "entropy: %s\n",$entropy;

is $zmh, 'ZN66r4pLT9zqqK91NkuMDnC6YvjSpq21cfmujg', 'testing getmnemonic';
   $tests_run++;


my $w3 = (split' ',$mnemo)[3];
is $w3, 'potato', "3rd word: $w3";
   $tests_run++;

is $entropy, $mmh, 'testing getentropy';
   $tests_run++;



}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


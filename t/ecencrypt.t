#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint decode_mbase encode_uuid);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {

my $msg = "Testing EC Encryption methods";
my $data = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($data);
my $hash = khash('SHA256',$data,'private key seed');
my $seed = &encode_uuid(substr($hash,16));

printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$data;
printf "zmh: %s\n",$zmh;
printf "seed: %s\n",$seed;

my $pair = { getPrivateKey($seed,salt => substr(unpack('H*',$hash),-5,4)) };
#printf "--- # pair %s---\n",Dump($pair);
my ($sku,$pku) = ($pair->{private}, $pair->{public});
printf "\e[31msku: %s\e[0m\n",$sku;
printf "pku: %s\n",$pku;


my $cipher = ecEncrypt($keys::pkb,&decode_mbase($sku));
printf "cipher: %s\n",$cipher;
print '-' x 32, "\n";
my $plain = ecDecrypt($keys::skb,$cipher);
my $plain58 = &encode_mbase58($plain);
printf "plain: %s\n",$plain58;

is $plain58, $sku, "testing ecDecryption for $sku";
   $tests_run++;


}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


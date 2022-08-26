#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic (@basic::EXPORT_OK);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite

my ($user,$pin) = ('michelc','2309');

DUT: {

my $msg = "Testing Registration";
my $data = pack('H*','015500').&varint(length($msg)).$msg;
my $zmh = &encode_mbase58($data);
my $hash = khash('SHA256',$data,'private key seed');
my $nonce = substr($hash,16);

printf "url: https://gateway.ipfs.io/ipfs/f%s\n",unpack'H*',$data;
printf "zmh: %s\n",$zmh;
printf "nonce: %s\n",&encode_uuid($nonce);

if (0) {
my $pair = { getPrivateKey($nonce,salt => substr(unpack('H*',$hash),-5,4)) };
#printf "--- # pair %s---\n",Dump($pair);
my ($sku,$pku) = ($pair->{private}, $pair->{public});
printf "\e[31msku: %s\e[0m\n",$sku;
printf "pku: %s\n",$pku;
}

# -----------------------------------------------------------
my $auth = &encode_base64("$user:$pin",'');
my $keypair = &ecKDF($auth,$hash, 'unsecure' => 1);
#printf "keypair: %s...\n",Dump($keypair);
my ($sks,$pks) = ($keypair->{private},$keypair->{public});
printf "sks: %s\n",$sks;
printf "pks: %s\n",$pks;
# -----------------------------------------------------------

my $seed = random(16);
printf "seed: %s\n",encode_uuid($seed);
my $wrap = { keyWrap($seed,$pks,$keys::skb,"token:login") };
printf "--- # wrap %s---\n",Dump($wrap);
my $cypher = $wrap->{cypher64};
printf "token: %s\n",$wrap->{cipher64};

my $unwrap = { keyUnwrap($cypher,$sks,"token:login") };
printf "--- # unwrap %s---\n",Dump($unwrap);
my $seed58 = $unwrap->{plain58};
my $seedr = decode_mbase($seed58);
printf "seedr: %s\n",encode_uuid($seedr);

my $secretid = &KH('SHA256',$unwrap->{secret_raw},$seedr);
my $eidentity = xorPlain($sku_prev,$secretid);
my $sku = xorPlain($secretid_prev,$LUT{$eidentity});

}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;


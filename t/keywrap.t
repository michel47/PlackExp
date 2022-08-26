#!/usr/bin/perl
#
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use Crypt::PK::ECC qw();
use basic (@basic::EXPORT_OK);
use keys (@keys::EXPORT_OK);

my$curve = 'secp256k1';
my $priv58 = 'ZaW1Nu8ZcFXDsbVmcTEGNHVdQkJeGxzzC5yesWnA5EvFH';
my $pub58 = 'ZZ3QXZd3a6JL2s1en2Kq5SeY9ThU9gzQKG4a2o8eqRsLh';

my $devid = '425acbb8-2315-49f3-9ba2-2f24bbbf48b2';
my $device = { &getKeyPair($devid, 'salt' => substr($devid,-5,4)) };
printf "devid: %s (pkd: %s)\n",$devid,$device->{public};

my $nonce = random(32);
my $nonce64 = &encode_mbase64($nonce);
printf "nonce58: %s\n",&encode_mbase58($nonce);
my $cypher = &keyWrap($devid,$pub58,$nonce64,"shipping devid");
printf "cypher64: %s\n",$cypher;
my $secret58 = &keyUnwrap($cypher,$priv58,"shipping devid");
my $secret = decode_mbase($secret58);
printf "secret58: %s\n",$secret58;
printf "secret16: %s\n",encode_uuid($secret);




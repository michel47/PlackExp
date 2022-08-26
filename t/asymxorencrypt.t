#!/usr/bin/env SITE=$(git rev-parse --show-toplevel) perl

BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use YAML::XS qw(Dump);
use keys (@keys::EXPORT_OK);
use basic qw(varint khash encode_mbase64 encode_mbase58 encode_mbase16 encode_base10 encode_uuid decode_mbase);
# --------------------------------------------------
my $tests_run = 0;
use Test::More tests => 2; # see also [1]: https://metacpan.org/pod/Test2::Suite


DUT: {
 my $sk1= 'Zfutw264XzVCfJHtKxsUGFBJ7pxhC5BJQFcQ7Uk4Z5AEs';
 my $pk1= ECC($sk1)->{public};
 printf "pk1: %s\n",$pk1;
 my $sk2= 'ZcGh3g3JLyZ6EVuQGe22AyVCKYu51TSsaZ5LPpr4qjfNT';
 printf "sk2: %s\n",$sk2;
 my $pk2= ECC($sk2)->{public};
 my $dhsecret_raw = DHSecret($sk1,$pk2);
 my $dhsecret10 = encode_base10($dhsecret_raw);
 is $dhsecret10, '33983282421739629327577216239477884415286747599743890815582050116314067790334', 'dhsecret check';
 $tests_run++;

 print "---\n";
 my $private = 'ZngLdc8JPsSYuJPLHFkNezV7xAY41gZPfyLJ9RWMQg44';
 my $pair = ECC($private);
 my $priv_raw = &decode_mbase($private);
 my $pub_raw = &decode_mbase($pair->{public});
 printf "pub58: %s\n",$pair->{public};
 printf "pub16: %s\n",encode_mbase16($pub_raw);
 printf "pub: %s (bi)\n",encode_base10($pub_raw);

 printf "priv58 %s\n",encode_mbase58($priv_raw);
 printf "priv16: %s\n",encode_mbase16($priv_raw);
 printf "priv: %s (bi)\n",encode_base10($priv_raw);
 print "--- encryption ...\n";
 printf "pk2: %s\n",$pk2;
 #printf "dhsecret: %s (%dc)\n",$dhsecret10,length($dhsecret10);
 #my $dhsecret_raw = decode_mbase('9'.$dhsecret10);
 printf "dhsecret64: %s\n",encode_mbase64($dhsecret_raw);
 printf "dhsecret16: %s\n",encode_mbase16($dhsecret_raw);
 printf "dhsecret: %s (bi)\n",encode_base10($dhsecret_raw);

 my $khash = &khash('SHA256',$dhsecret_raw);
 printf "khash58: %s\n",encode_mbase58($khash);
 printf "khash16: %s\n",encode_mbase16($khash);
 printf "khash: %s (bi)\n",encode_base10($khash);
 my $skey = &xorPlain($khash,$priv_raw);
 printf "skey58: %s\n",encode_mbase58($skey);
 printf "skey16: %s\n",encode_mbase16($skey);
 printf "skey: %s (bi)\n",encode_base10($skey);

 print "--- decryption ...\n";
 printf "sk2: %s\n",$sk2;
 printf "{skey,pk1}: %s,%s\n",encode_mbase58($skey),$pk1;
 my $dhsecret2 = DHSecret($sk2,$pk1);
 printf "dhsecret64: %s\n",encode_mbase64($dhsecret2);
 printf "dhsecret16: %s\n",encode_mbase16($dhsecret2);
 my $khash2 = &khash('SHA256',$dhsecret2);
 printf "khash58: %s\n",encode_mbase58($khash2);
 my $plain = &xorPlain($khash,$skey);
 printf "plain58 %s\n",encode_mbase58($plain);
 printf "plain16: %s\n",encode_mbase16($plain);
 printf "plain: %s (bi)\n",encode_base10($plain);
 print "---\n";

 is $plain, $priv_raw, 'decrypted private key';
 $tests_run++;
 

}

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;
1;

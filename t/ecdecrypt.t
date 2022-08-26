BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

print "--- # $0\n";
my $tests_run = 1;
use Test::More tests => 1; # see also [1]: https://metacpan.org/pod/Test2::Suite


use basic (@basic::EXPORT_OK);
use keys qw();

my $cleartext = khash('SHA256','123 polichinelle');
print '# ','-'x64,"\n";
printf "clear64: %s\n",&encode_mbase64($cleartext);
my $cipher64 = keys::ecEncrypt($keys::pkb,$cleartext);
my $cipher = &decode_mbase64($cipher64);
printf "cipher16: %s\n",&encode_mbase16($cipher);
printf "cipher58: %s\n",&encode_mbase58($cipher);
printf "cipher64: %s\n",$cipher64;
print '# ','-'x32,"\n";
my $plain = keys::ecDecrypt($keys::skb,$cipher64);
printf "plain16: %s\n",&encode_mbase16($plain);
printf "plain64: %s\n",&encode_mbase64($plain);
print '# ','-'x64,"\n";

is $cleartext, $plain, "testing en/decrypt from keys package"; 

done_testing($tests_run);
print "...\n";
# --------------------------------------------------
exit $?;



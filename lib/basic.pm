#
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

package basic;
require Exporter;
@ISA = qw(Exporter);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

use strict;

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',(caller(0)||caller(1));
# -----------------------------------------------------------------------
our $apicreds = '[CYPHER]c2NyeXB0AA8AAAAIAAAAAUcKJeX5Zur5AgVxL8D8RjoVxhYyPR5qLDTgxu6NGcrmJXoipg+977ZKq45NHz5aR8HZEizwNmkCwIQDvxrOgFdxvhmC2gjBXi9oxk7OpEE/eiWily2kF8zpBeLrZ3oHbnNU4SRgDCaOsdIeMiUN1xbNQSsXAKBGrw+R9Ynlj6ia47uSNA==[CLEAR]';
#
use Time::HiRes qw(time);
my $time = time;

our $DBUG;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = (gmtime(int$time));
our $DBUGF = sprintf"%s/_data/dbug-D%d.yml",$ENV{SITE},$yday+1; $DBUGF =~ s,_site/,,;
open $DBUG,'>>',$DBUGF or warn $!; binmode($DBUG, ":utf8");
my $h = select $DBUG; $|=1; select($h); # autoflush for $DBUG

our $SLOG;
my $SLOGF = sprintf"%s/_data/seclog.yml",$ENV{SITE},; $SLOGF =~ s,_site/,,;
open $SLOG,'>>',$SLOGF or warn $!; binmode($SLOG, ":utf8");

sub debug(@) {
  my $callee = (caller(1))[3];
  $callee =~ s/.*:://o;
  my $tics = time();
  my $ticns = $tics * 1000_000;
  my $fmt = shift;
  if ($fmt !~ m/\n$/) { $fmt .= "\n"; }
  printf $DBUG '%u: %s.'.$fmt,$ticns,$callee,@_;
}
sub ldate { # return a human readable date ... but still sortable ...
  my $tic = int($_[0]);
  my ($sec,$min,$hour,$mday,$mon,$yy) = (localtime($tic))[0..5];
  my ($yr4,$yr2) =($yy+1900,$yy%100);
  my $date = sprintf '%04u-%02u-%02u %02u.%02u.%02u',
             $yr4,$mon+1,$mday, $hour,$min,$sec;
  return $date
}

sub seclog(@) {
  my $callee = (caller(1))[3];
  $callee =~ s/.*:://o;
  my $tics = time();
  my $ticns = $tics * 1000_000;
  my $fmt = shift;
  if ($fmt !~ m/\n$/) { $fmt .= "\n"; }
  printf $SLOG '%u: %s.'.$fmt,$ticns,$callee,@_;
}
# ------------------------------------------------



sub get_creds($) {
  use secrets qw(get_pass);
  our $auth64;
  my $token = shift || $apicreds;
  if (! defined $auth64) {
    my $pass = &get_pass();
    # apiu:$apr1$s9BmOq49$y8Zmau6v6Hygv.lHNvhcg.
    $auth64 = &clarify($token,$pass);
  } else {
    debug "auth: %s\n",$auth64;
  }
  return $auth64;
}

sub clarify() { # Ex: my $clear = &clarify('[REDACTED]abc[CLEAR]');
 our $n;
 my $callee = 'clarify';
 use secrets qw();
 use Crypt::Scrypt;
 use MIME::Base64 qw(decode_base64 encode_base64);
 my ($string,$password) = @_;
 my $secret;
 if (defined $password && $password ne '') {
    debug qq'password: %s\n',$password;
    $secret = $password
 } else {
   $secret = $ENV{REDACTION_SECRET} || $secrets::secrets->{default};
   debug qq'secret: %s\n',$secret;
 }
 my $scrypt = Crypt::Scrypt->new(key => $secret, max_mem => 0, max_mem_frac => 0.5, max_time => 10);
 my $cipher64 = ($string =~ m/\[CIPHER](.*)\[CLEAR]/) ? $1 : encode_base64($scrypt->encrypt('unintelligible text'),'');
 my $cipher64p = $cipher64; $cipher64p =~ tr/+\//-_/;
 debug qq'string: %s\n',$string;
 debug qq'cipher64.%u: %s\n',$n++,$cipher64p; # n++ instead of time to test predictability
 my $cipher = decode_base64($cipher64);
 debug qq'cipher16: f%s\n',unpack'H*',$cipher;
 my $plain = $scrypt->decrypt($cipher);
 debug qq'plain: %s\n',$plain;
 return $plain
}

sub redact() {
 our $n;
 use secrets qw();
 use Crypt::Scrypt;
 use MIME::Base64 qw(encode_base64);
 my ($string,$password) = @_;
 my $secret = $password || $ENV{REDACTION_SECRET} || $secrets::secrets->{default};
 my $scrypt = Crypt::Scrypt->new(key => $password, max_mem => 0, max_mem_frac => 0.1, max_time => 2);
 my $plain = ($string =~ m/\[[^]]*REDACT[^]]*](.*)\[PLAIN]/) ? $1 : $string;

 my $cipher = $scrypt->encrypt($plain);
 my $cipher64 = encode_base64($cipher,'');
 printf qq'cipher64.%s: %s\n',$n++,$cipher64; # /!\ not deterministic !
 return sprintf '[CIPHER]%s[CLEAR]',$cipher64
}

sub version {
  #y $intent = "get time based version string and a content based build tag";
  #y ($atime,$mtime,$ctime) = (lstat($_[0]))[8,9,10];
  my @times = sort { $a <=> $b } (lstat($_[0]))[9,10]; # ctime,mtime
  my $vtime = $times[-1]; # biggest time...
  my $version = &rev($vtime);

  if (wantarray) {
     my $shk = &get_shake(160,$_[0]);
     debug "%s : shk:%s\n",$_[0],$shk if $dbug;
     my $pn = unpack('n',substr($shk,-4)); # 16-bit
     my $build = &word($pn);
     return ($version, $build);
  } else {
     return sprintf '%g',$version;
  }
}
# -----------------------------------------------------------------------
sub rev { # get revision numbers
  my ($sec,$min,$hour,$mday,$mon,$yy,$wday,$yday) = (localtime($_[0]))[0..7];
  my $rweek=($yday+&fdow($_[0]))/7;
  my $rev_id = int($rweek) * 4;
  my $low_id = int(($wday+($hour/24)+$min/(24*60))*4/7);
  my $revision = ($rev_id + $low_id) / 100;
  return (wantarray) ? ($rev_id,$low_id) : $revision;
}
# -----------------------------------------------------------------------
sub fdow { # get January first day of week
   my $tic = shift;
   use Time::Local qw(timelocal);
   ##     0    1     2    3    4     5     6     7
   #y ($sec,$min,$hour,$day,$mon,$year,$wday,$yday)
   my $year = (localtime($tic))[5]; my $yr4 = 1900 + $year ;
   my $first = timelocal(0,0,0,1,0,$yr4);
   our $fdow = (localtime($first))[6];
   #debug "1st: %s -> fdow: %s\n",&hdate($first),$fdow;
   return $fdow;
}
# -----------------------------------------------------------------------
sub khash { # keyed hash
   use Crypt::Digest qw();
   my $alg = shift;
   my $data = join'',@_;
   my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
   my $hash = $msg->digest();
   return $hash;
}
# -----------------------------------------------------------------------
sub get_shake { # use shake 256 because of ipfs' minimal length of 20Bytes
  use Crypt::Digest::SHAKE;
  my $len = shift;
  local *F; open F,$_[0] or do { warn qq{"$_[0]": $!}; return undef };
  #binmode F unless $_[0] =~ m/\.txt/;
  my $msg = Crypt::Digest::SHAKE->new(256);
  $msg->addfile(*F);
  my $digest = $msg->done(($len+7)/8);
  return $digest;
}
# -----------------------------------------------------------------------
sub keyw { # get a keyword from a hash (using 8 Bytes)
  my $hash=shift;
  my $o = (length($hash) > 11) ? -11 : -8;
  my $n = unpack'N',substr($hash,-$o,8);
  my $kw = &word($n);
  return $kw;
}
# -----------------------------------------------------------------------
sub word { # 20^4 * 6^3 words (25bit worth of data ...)
 use integer;
 my $n = $_[0];
 my $vo = [qw ( a e i o u y )]; # 6
 my $cs = [qw ( b c d f g h j k l m n p q r s t v w x z )]; # 20
 my $str = '';
 if (1 && $n < 26) {
 $str = chr(ord('a') +$n%26);
 } else {
 $n -= 6;
 while ($n >= 20) {
   my $c = $n % 20;
      $n /= 20;
      $str .= $cs->[$c];
   #print "cs: $n -> $c -> $str\n";
      $c = $n % 6;
      $n /= 6;
      $str .= $vo->[$c];
   #print "vo: $n -> $c -> $str\n";

 }
 if ($n > 0) {
   $str .= $cs->[$n];
 }
 return $str;
 }
}
# ------------------------------------------------
sub varint {
  my $i = shift;
  my $bin = pack'w',$i; # Perl BER compressed integer
  # reverse the order to make is compatible with IPFS varint !
  my @C = reverse unpack("C*",$bin);
  # clear msb on last nibble
  my $vint = pack'C*', map { ($_ == $#C) ? (0x7F & $C[$_]) : (0x80 | $C[$_]) } (0 .. $#C);
  return $vint;
}
# ------------------------------------------------
# multihash decode
sub decode_mbase($) {
  my $data = shift;
  my $data_raw;
  if ($data =~ m/^9[0-9]+$/) {
      $data_raw = &decode_mbase10($data) ;
  } elsif ($data =~ m/^[0-9a-f\-]+$/ && length($data) % 2 == 0 ) {
    my $data16 = $data; $data16 =~ tr /-//d;
    $data_raw = pack'H*',$data16;
  } elsif (length($data) % 16) {
    if ($data =~ m/^m/) {
      $data_raw = &decode_mbase64($data) ;
    } elsif ($data =~  m/^Z/s) {
      $data_raw = &decode_mbase58($data) ;
    } elsif ($data =~  m/^f[0-9a-f]+$/s) {
      $data_raw = &decode_mbase16($data) ;
    } elsif ($data =~  m/^9\d+$/s) {
      $data_raw = &decode_mbase10($data) ;
    } else {
      $data_raw = $data;
    }
  } elsif ($data =~ m/=$/) {
    $data_raw = &decode_base64($data) ;
  } else {
    $data_raw = $data;
  } 
  return $data_raw;
}
# ------------------------------------------------
# for binary data ...
sub encode_uuid {
  my $data = join'',@_;
  if (length($data) == 16) {
    return join'-',unpack'H8H4H4H4H12',$data;
  } else {
    return join'-',unpack'H8H4H4H4H12H8H8H*',$data;
  }
}
sub encode_mbase16 {
  my $mh = sprintf'f%s',unpack'H*',join'',@_;
}
sub decode_mbase16 {
  return pack'H*',substr($_[0],1);
}
# ------------------------------------------------
# seeds, cypher and IV
sub encode_mbase64 {
  use MIME::Base64 qw(encode_base64);
  my $mh = sprintf'm%s',&encode_base64(join('',@_),'');
  $mh =~ s/=+$//;
  return $mh;
}
sub decode_mbase64 {
  use MIME::Base64 qw(decode_base64);
  return &decode_base64(substr($_[0],1));
}
# ------------------------------------------------
sub encode_mbase10 {
  my $mh = sprintf'9%s',uc&encode_base10(@_);
  return $mh;
}
sub decode_mbase10 {
  return &decode_base10(substr($_[0],1));
}
# ------------------
sub encode_base10 {
  use Math::BigInt;
  use Math::Base36 qw();
  my $n = Math::BigInt->from_bytes(shift);
  return $n;
}
sub decode_base10 {
  use Math::BigInt;
  use Math::Base36 qw();
  my $bin = Math::BigInt->new($_[0])->as_bytes();
  return $bin;
}
# ------------------------------------------------
sub encode_mbase36 {
  my $mh = sprintf'K%s',uc&encode_base36(@_);
  return $mh;
}
sub decode_mbase36 {
  return &decode_base36(substr($_[0],1));
}
# ------------------
sub encode_base36 {
  use Math::BigInt;
  use Math::Base36 qw();
  my $n = Math::BigInt->from_bytes(shift);
  my $k36 = Math::Base36::encode_base36($n,@_);
  #$k36 =~ y,0-9A-Z,A-Z0-9,;
  return $k36;
}
sub decode_base36 {
  use Math::BigInt;
  use Math::Base36 qw();
  #$k36 = uc($_[0])
  #$k36 =~ y,A-Z0-9,0-9A-Z;
  my $n = Math::Base36::decode_base36($_[0]);
  my $bin = Math::BigInt->new($n)->as_bytes();
  return $bin;
}
# ------------------------------------------------
sub encode_mbase58 {
  my $mh = sprintf'Z%s',&encode_base58f(@_);
  return $mh;
}
sub decode_mbase58 {
  return &decode_base58f(substr($_[0],1));
}
# -------------------
sub encode_base58f { # flickr
  use Math::BigInt;
  use Encode::Base58::BigInt qw();
  my $bin = join'',@_;
  my $bint = Math::BigInt->from_bytes($bin);
  my $h58 = Encode::Base58::BigInt::encode_base58($bint);
  # $h58 =~ tr/a-km-zA-HJ-NP-Z/A-HJ-NP-Za-km-z/; # btc
  return $h58;
}
sub decode_base58f {
  use Carp qw(cluck);
  use Math::BigInt;
  use Encode::Base58::BigInt qw();
  my $s = $_[0];
  #$s =~ tr/A-HJ-NP-Za-km-zIO0l/a-km-zA-HJ-NP-ZiooL/; # btc
  $s =~ tr/IO0l/iooL/; # forbidden chars
  #printf "s: %s\n",unpack'H*',$s;
  my $bint = Encode::Base58::BigInt::decode_base58($s) or warn "$s: $!";
  cluck "error decoding $s!" unless $bint;
  my $bin = Math::BigInt->new($bint)->as_bytes();
  return $bin;
}
# -----------------------------------------------------------------------
sub readfile { # Ex. my $content = &readfile($filename);
  #y $intent = "read a (simple) file";
  my $file = shift;
  if (! -e $file) {
    print "// Error: readfile.file: ! -e $file\n";
    return undef;
  }
  local *F; open F,'<',$file; binmode(F);
  debug "// reading file: $file\n";
  local $/ = undef;
  my $buf = <F>;
  close F;
  return $buf;
}
# -----------------------------------------------------------------------
sub shortkey {
  if (defined $_[0]) {
    my $qm = shift;
    if ($qm =~ m/^(?:Qm|[Zmf])/) {
      return substr($qm,0,5).'..'.substr($qm,-4);
    } else {
      return substr($qm,0,6).'..'.substr($qm,-3);
    }
  } else {
    return 'undefined';
  }
}
# -----------------------------------------------------------------------
sub get_ip {
  my $env = $_[0];
  my $dotip;
  if (exists $env->{HTTP_CLIENT_IP}) {
    $dotip = $env->{HTTP_CLIENT_IP};
  } elsif (exists $env->{HTTP_X_REAL_IP}) {
    $dotip = $env->{HTTP_X_REAL_IP};
  } elsif (exists $env->{REMOTE_ADDR}) {
    $dotip = $env->{REMOTE_ADDR};
  } else {
    $dotip = &get_publicip();
  }
  if ($dotip =~ m/^127/) {
    $dotip = &get_publicip();
  }
  return $dotip;
}
sub get_publicip { # my $ip = &get_publicip();
  #y $intent = "return the client public IP from the nginX remote address variable"
  use LWP::UserAgent qw();
  my $ip;
  my $ua = LWP::UserAgent->new();
  my $url = 'http://api.safewatch.care/psgi/remote_addr.txt';
  $ua->timeout(3);
  my $resp = $ua->get($url);
  if ($resp->is_success) {
    my $content = $resp->decoded_content;
    $ip = (split("\n",$content))[0];
  } else{
    $ip = '0.0.0.0';
  }
  return $ip;
}
# -----------------------------------------------------------------------
sub writefile { # Ex. &writefile($filename, $data1, $data2);
  #y $intent = "write a (simple) file";
  my $file = shift;
  local *F; open F,'>',$file; binmode(F);
  debug "// storing file: $file\n";
  for (@_) { print F $_; }
  close F;
  return $.;
}
# -----------------------------------------------------------------------
sub appendfile { # Ex. &appendfile($filename, $data1, $data2);
  #y $intent = "append a file with data";
  my $file = shift;
  use Cwd qw(); my $pwd = &Cwd::cwd();
  if (! -e $file) {
    if ($file !~ m,^/,) {
      $file = $ENV{SITE} . '/' . $file;
    }
  }
  local *F; open F,'>>',$file or warn $!; binmode(F);
  debug "// appending file: $file (pwd: $pwd)";
  for (@_) { print F $_; }
  printf "at =%u.\n",tell(F);
  close F;
  return $.;
}
# -----------------------------------------------------------------------
1;

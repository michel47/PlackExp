#
# Intent:
#  create keys for file encryption and provide user keys to decrypt it.
#
# Note:
#   This work has been done during my time freelancing
#   for PaladinAI at Toptal as Doctor I·T
# 
# -- PublicDomain CC0 drit, 2021; https://creativecommons.org/publicdomain/zero/1.0/legalcode --
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
#
package keys;
require Exporter;
@ISA = qw(Exporter);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

use strict;
use basic qw(debug version);

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------
my ($red,$green,$dcyan,$grey,$nocolor) = ( "\e[31m", "\e[1;32m", "\e[2;36m", "\e[0;90m", "\e[0m");

use YAML::XS qw(Dump);
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(hmac_sha256);
use Bitcoin::Mnemonic qw(entropy_to_bip39_mnemonic bip39_mnemonic_to_entropy gen_bip39_mnemonic);
use basic qw(seclog khash encode_mbase64 encode_mbase16 encode_mbase58 decode_mbase64);

our $appid = $ENV{APP_SECRETID} || '59d95bef-71f3-44e9-ae61-78dab20711d8';
my $app = { &getKeyPair($appid,'salt' => substr($appid,-5,4)) };
our $brokerid = $ENV{BROKER_SECRET} || '989e126c-4997-432e-b73b-57320a4e1c32';
my $broker = { &getKeyPair($brokerid,'salt' => substr($brokerid,-5,4)) };

my $pka = $app->{public};
printf "pka: %s\n",$pka;
our $pkb = $broker->{public};
our $skb = $broker->{private}; 
#seclog "skb: %s\n",$skb; # /!\ plain text
printf "\e[31mskb: %s\e[0m\n",$skb; # /!\ plain text
printf "pkb: %s\n",$pkb;
printf "fpb: %s\n",scalar fprint($skb,$pkb,'broker' => $skb);

sub getShard { # Ex. my $nid = &getShard($token);
 use basic qw(encode_base36 shortkey);
 my ($pk,$name,$typ) = split('$',$_[0]);
 debug "get a 13 character namespace identifier for %s (%s %s)", join(',',&shortkey($pk),@_[1..$#_]),$name,&botname($pk);
 #print "get_nid.\$#_: $#_\n";
 my $len = ($#_ > 0) ? pop : 13;
 my $sha2 = &khash('SHA256',@_);
 my $ns36 = &encode_base36($sha2);
 debug "ns36: %s",$ns36;
 my $shard = substr($ns36,0,$len);
 return lc $shard;
}
sub getuuid($) {
  use Data::UUID;
  my $seed = shift;
  my $oid = sprintf'uid.seed.%s',$seed;
  my $ug = Data::UUID->new;
  my $uuidv5 = $ug->create_from_name_str(NameSpace_OID, "$oid");
  return lc $uuidv5
}

sub get_uuid {
  use Data::UUID;
  my $pku = shift;
  my $ug = Data::UUID->new;
  my $url = sprintf'https://api.safewatch.care/api/v0/public/name?pubkey=%s',$pku;
  #my $md5 = khash('MD5',$url);
  #my $sha1 = khash('SHA1',$url);
  my $uuidv5 = $ug->create_from_name_str(NameSpace_URL, "$url");
  return lc $uuidv5
}

# -----------------------------------------------
# ex: xdg-open http://0.0.0.0:5000/?seed=abcd1234edfg5678 (12 words min)
sub getMnemonic {
  my $data = shift;
  use basic qw(decode_mbase);
  my $data_raw = decode_mbase($data);
  #printf "data_raw: %s\n",unpack'H*',$data_raw;
  debug qq'compute memonic for %s',&encode_base64($data_raw);
  my $mnemonic = &entropy_to_bip39_mnemonic (entropy => $data_raw, language => 'en');
  debug "mnemonic: %s\n",$mnemonic;
  return $mnemonic;
}
sub getEntropy {
  my  $args = { @_ };
  my $mnemonic;
  if (exists $args->{mnemonic}) {
     if (ref($args->{mnemonic}) eq 'ARRAY') {
        $mnemonic = join' ',@{$args->{mnemonic}};
     } else {
        $mnemonic = $args->{mnemonic};
     }
  } else {
    my $obj = shift;
    if (ref($obj) eq 'ARRAY') {
       $mnemonic = join' ',@{$obj};
    } else {
       $mnemonic = $obj;
    }
  }
  #printf "mnemonic: %s\n",$mnemonic;
  my $entropy;
  my $entropy_raw = &bip39_mnemonic_to_entropy(mnemonic => $mnemonic);
  use basic qw(encode_mbase58 encode_mbase64 encode_base64);
  if (exists $args->{format}) { 
    if($args->{format} eq 'uuid') {
      $entropy = join'-', unpack'H8H4H4H4H12',$entropy_raw;
    } elsif ($args->{format} eq 'b58') {
      $entropy = &encode_mbase58($entropy_raw);
    } elsif ($args->{format} eq 'b64') {
      $entropy = &encode_base64($entropy_raw);
    } elsif ($args->{format} eq 'b64mh') {
      $entropy = &encode_mbase64($entropy_raw);
    } else {
      $entropy = &encode_mbase16($entropy_raw);
    }
  } else { 
      $entropy = join'-',unpack'H8H4H4H4H*',$entropy_raw;
  }
  return $entropy;
}
# -----------------------------------------------
#
sub register($) {
   my $secret = shift;
   my $pkv = shift;
   my $secret_raw = &decode_mbase($secret);
   my $keypair = { &getKeyPair($secret) };

   my $uuid = &swissnumber($keypair->{public},$keypair->{private});
   debug "uuid: %s\n",$uuid;
   my $dhsecret1 = &DHSecret($skb,$pkv); # validator
   my $dhsecret2 = &DHSecret($skb,$pka); # application

   my $recoverkey = random(length($secret_raw));
   # secret derived key
   my $sdk = &khash('SHA256',$dhsecret1,$dhsecret2,"secret registration for $pkv");
   my $SN = xorEncrypt($secret_raw,$sdk);
   # $secret_raw = xorDecrypt($SN,$sdk);

   return ($uuid, $recoverkey);
}
sub recover($) {
   my ($uuid,$secret) = @_;

}
sub xencKDF($$$$) { # Ex. my $xku = &xencKDF($sko,$pku,$dpk,$mutaddr);
  use basic qw(decode_mbase58 encode_mbase58);
  my ($ownKey,$pubKey,$seckey,$URI) = @_;
  my $seckey_raw = &decode_mbase58($seckey) if ($seckey =~ m/^Z/);
  my $dhusecret = &DHSecret($ownKey,$pubKey);
  my $khashu = &khash('SHA256',$URI,$dhusecret); # allays keyed-hash "secret part" of xor argument
  seclog "khash: %s\n", &encode_mbase58($khashu); # /!\ secret in plain text
  my $acckey = &xorEncrypt($seckey,$khashu);
  my $acckey58 = &encode_mbase58($acckey);
  return $acckey58;
}
sub xdecKDF($$$$) { # Ex. my $dpk = &xencKDF($sku,$pko,$xku,$mutaddr);
  use basic qw(decode_mbase58 encode_mbase58);
  my ($privKey,$pubKey,$acckey,$URI) = @_;
  $acckey = &decode_mbase58($acckey) if ($acckey =~ m/^Z/);
  my $dhsecret = DHSecret($privKey,$pubKey);
  my $khash = &khash('SHA256',$URI,$dhsecret); # allays keyed-hash "secret part" of xor argument
  seclog "khash: %s\n", &encode_mbase58($khash); # /!\ secret in plain text
  my $seckey = &xorDecrypt($acckey,$khash);
  debug "acckey: %s\n", &encode_mbase58($acckey);
  debug "xdecKDF.seckey: %s\n", &encode_mbase58($seckey);
  #y $seckey58 = &encode_mbase58($seckey);
  return $seckey;
}

# -----------------------------------------------
sub getKeyPair(@) {
   #y $intent qq'compute keypair from a uuid';
   my $args = { @_ };
   #printf "--- # args: %s---\n",YAML::XS::Dump($args);
   my $seed;
   if (exists $args->{seed}) {
      $seed = $args->{seed};
   } else {
      $seed = shift;
      $args = { @_ };
   }
   #my $pkd = $args->{devid};

   my $seed16 = $seed; $seed16 =~ tr/-//d;
   #debug "seed16: f%s (%dc)\n",$seed16, length($seed16);
   my $seed_raw = pack'H*',$seed16;
   #y $seed58 = &encode_mbase58($seed_raw);
   my $seed64 = &encode_base64($seed_raw,'');
   debug "seed: %s (%dB)\n",$seed64, length($seed_raw);
   my $ns = sprintf "seed %d\0", length($seed_raw);
   my $khash = substr(&khash('SHA256',$ns,$seed_raw),0,240/8);
   my $salt = pack('H4',$args->{salt}) || random(2);
   #debug "khash: %s\n",unpack'H*',$khash;
   seclog "salt: %s\n",unpack'H*',$salt;
   my $sku_raw = $khash.$salt;
   my $sku = encode_mbase58($khash.$salt);
   debug "sku: %s\n",$sku;

   my $keypair = &ECC($sku_raw);
   use Time::HiRes qw(time);
   my $tics = time;
   my $ticns = int($tics * 1000_000);

   $keypair->{timestamp} = $ticns;

   if (wantarray) {
      my $mnemo = getMnemonic($seed_raw);
      debug 'mnemo: %s',$mnemo;
      $keypair->{mnemonic} = $mnemo;
      $keypair->{seed} = $seed;
      $keypair->{salt} = unpack('H4',$salt);

      debug "keypair: %s---\n",Dump($keypair);
      return %{$keypair};
   } else {
      return $keypair->{public};
   }
}
# -----------------------------------------------
sub getPublicKey(@) { return &getKeyPair(@_); }
sub getPrivateKey(@) {
   my $pair = { &getKeyPair(@_) };
   #printf "--- # pair: %s---\n",Dump($pair);
   return (wantarray) ? %$pair : $pair->{private};
}
# -----------------------------------------------
sub ECC {
   my $curve = 'secp256k1';
   use Crypt::PK::ECC;
   my $pk = Crypt::PK::ECC->new();
   my $secretkey = shift;
   my ($private_raw,$public_raw);
   if (defined $secretkey) { # key derivation ...
      my $secret_raw = ($secretkey =~ m/^Z/ && length($secretkey) != 32) ?
                    &decode_mbase58($secretkey) : $secretkey;
      printf "secretkey: %s (%uB)\n",unpack('H*',$secret_raw),length($secret_raw);
      my $priv = $pk->import_key_raw($secret_raw, $curve);
      $private_raw = $priv->export_key_raw('private_compressed');
      debug "private: %s (imported)",&encode_mbase58($private_raw);
   } else { # key generation ...
      $pk->generate_key($curve);
      $private_raw = $pk->export_key_raw('private_compressed');
   }
   my $seckey58 = &encode_mbase58($private_raw);
   my $public_raw = $pk->export_key_raw('public_compressed');
   my $pubkey58 = &encode_mbase58($public_raw);
   my $pair = {
      curve => $curve,
      public => $pubkey58,
      private => $seckey58,
   };
   return $pair;
}
# -----------------------------------------------
sub KH { # keyed hash
   use Crypt::Digest qw();
   my $alg = shift;
   my $data = join'',@_;
   my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
   my $hash = $msg->digest();
   return $hash;
}
# -----------------------------------------------
sub KHMAC($$@) { # Ex. my $kmac = &KHMAC($algo,$secret,$nonce,$message);
  #y $intent = qq'to compute a keyed hash message authentication code';
  use Crypt::Mac::HMAC qw();
  my $algo = shift;
  my $secret = shift;
  #printf "KHMAC.secret: f%s\n",unpack'H*',$secret;
  my $digest = Crypt::Mac::HMAC->new($algo,$secret);
     $digest->add(join'',@_);
  return $digest->mac;
}

sub DHSecret { # Ex my $secret = DHSecret($sku,$pku);
  #y $intent = "reveals the share secret between 2 parties !";
  my ($privkey58,$pubkey58) = @_;
  my $public_raw = &decode_mbase58($pubkey58);
  my $private_raw = &decode_mbase58($privkey58);

  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
  my $sk  = Crypt::PK::ECC->new();
  my $priv = $sk->import_key_raw($private_raw, $curve);
  my $pk = Crypt::PK::ECC->new();
  my $pub = $pk->import_key_raw($public_raw ,$curve);
  my $secret_raw = $priv->shared_secret($pub);
  my $secret58 = &encode_mbase58($secret_raw);
  my $secret64 = &encode_base64($secret_raw,'');

  my $public = $priv->export_key_raw('public_compressed');
  my $public58 = &encode_mbase58($public);

  use basic qw(shortkey);
  printf "${red}DH%s(%s): %s (%s)${nocolor}\n",substr($privkey58,-3),&shortkey($pubkey58),&shortkey($secret64),&shortkey($secret58);

  my $obj = {
    secret_raw => $secret_raw,
    origin => $public58,
    public => $pubkey58,
    secret64 => $secret64,
    secret58 => $secret58
  };
  return wantarray ? %{$obj} : $secret_raw;
}

sub keyWrap($$$) { # Ex. my $cypher = &keyWrap($seckey,$pkr,$nonce,$intent);
  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
  my $sk = Crypt::PK::ECC->new();
  my $pk = Crypt::PK::ECC->new();
  my ($cleartext,$pub58,$nonce,$intent) = @_;
  my $clear_raw = &decode_mbase($cleartext);
  my $pub_raw = &decode_mbase($pub58);
  my $priv_raw = &decode_mbase($nonce);
  my $priv = $sk->import_key_raw($priv_raw, $curve);
  my $pub = $pk->import_key_raw($pub_raw, $curve);
  my $dhsecret = $priv->shared_secret($pub);

  my $pub = $sk->export_key_raw('public_compressed');
  printf "pubkey: %s\n",&encode_mbase58($pub);
  my $len = length($clear_raw);
  my $dkey = substr(&khash('SHA256',$intent,$dhsecret),0,$len);
  my $cipher = xorPlain($dkey,$clear_raw);
  if (1) {
    printf "clear : %s\n",&encode_mbase16($clear_raw);
    printf "pub : %s\n",&encode_mbase16($pub);
    printf "dhsec : %s\n",&encode_mbase16($dhsecret);
    printf "dkey  : %s\n",&encode_mbase16($dkey);
    printf "cipher: %s\n",&encode_mbase16($cipher);
  }
  my $cypher64 = &encode_mbase64($pub.$cipher);
  return $cypher64;
}
sub keyUnwrap($$) { # Ex. my $seckey = &keyUnwrap($cypher,$skr,$intent);
  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
  my $sk = Crypt::PK::ECC->new();
  my $pk = Crypt::PK::ECC->new();
  my ($cypher64,$priv58,$intent) = @_;
  my $cypher = &decode_mbase($cypher64);
  my $pub_raw = substr($cypher,0,33);
  my $cipher = substr($cypher,33);
  my $len = length($cipher);
  my $priv_raw = &decode_mbase($priv58);
  my $priv = $sk->import_key_raw($priv_raw, $curve);
  my $pub = $pk->import_key_raw($pub_raw, $curve);
  my $dhsecret = $priv->shared_secret($pub);
  my $dkey = substr(&khash('SHA256',$intent,$dhsecret),0,$len);
  my $plain_raw = xorPlain($dkey,$cipher);
  if (1) {
    printf "cipher: %s\n",&encode_mbase16($cipher);
    printf "pub : %s\n",&encode_mbase16($pub_raw);
    printf "dhsec : %s\n",&encode_mbase16($dhsecret);
    printf "dkey  : %s\n",&encode_mbase16($dkey);
    printf "plain : %s\n",&encode_mbase16($plain_raw);
  }
  my $plain = &encode_mbase58($plain_raw);
  return $plain
}

sub ecEncrypt($$) {
  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
   my ($pub58,$cleartext) = @_;
   my $pub_raw = &decode_mbase58($pub58);
   debug "pubkey: %s\n",$pub58;
   if ($cleartext =~ /[\000-\031\177-\377]/o) { # binary ?
     debug "cleartext58: %s\n",&encode_mbase58($cleartext);
   } else {
     debug "cleartext: %s\n",$cleartext;
   }
   debug "recipient: %s\n",$pub58;
   my $pk = Crypt::PK::ECC->new();
   my $pub = $pk->import_key_raw($pub_raw, $curve);
   #printf "pub: %s\n",&encode_mbase58($pub->export_key_raw('public_compressed'));
   my $cipher = $pk->encrypt(substr($cleartext."\0"."\xA5"x31,0,32), 'SHA256');
   my $cipher64 = encode_mbase64($cipher);
   return $cipher64;
}
sub ecDecrypt($$) {
  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
   my ($priv58,$cipher64) = @_;
   my $priv_raw = &decode_mbase58($priv58);
   my $cipher = decode_mbase64($cipher64);
   debug "privkey: %s\n",$priv58;
   debug "cipher: %s\n",&encode_mbase64($cipher);
   my $sk = Crypt::PK::ECC->new();
   my $priv = $sk->import_key_raw($priv_raw, $curve);
   #printf "key2hash: %s...\n",Dump($sk->key2hash);
   my $pub = $sk->export_key_raw('public_compressed');
   printf "recipient: %s\n",&encode_mbase58($pub);
   my $plain = $sk->decrypt($cipher);
   if ($plain =~ /[\000-\031\177-\377]/o) { # binary ?
     debug "plain58: %s\n",&encode_mbase58($plain);
   } else {
     debug "plain: %s\n",$plain;
   }
   return $plain;
}


sub xorEncrypt($$) { # Ex. $cipher = xorEncrypt($data,$key,$seed);
   #y $intent = "xor encrypt a key";
  my ($d,$k,$s) = @_; # /!\ insecure if k smaller than d
  my $s ||= random(8);
  #$s = pack'N',0;
  my @data = (0,unpack'N*',$d);
  my @key =(0,unpack'N*',$k."\0"x3);
  debug "s: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$s;
  debug "d: %s\n",join'.',map { sprintf'%08x',$_ } @data;
  debug "k: %s\n",join'.',map { sprintf'%08x',$_ } @key;
  my @res = map { unpack'N',$s } (0 .. $#data);
  #$res[-1] = $s;
  debug "r: %s\n",join'.',map { sprintf'%08x',$_ } @res;
  my $mod = scalar(@key);
  for my $i (0 .. $#data) {
    $res[$i] = $res[$i-1] ^ $data[$i] ^ $key[$i % $mod];
    debug "%d: %08X = %08X ^ %08X ^ %08X\n",$i,$res[$i],$res[$i-1],$data[$i],$key[$i % $mod] if $dbug;
  }
  my $x = pack 'N*',@res;
  debug "x: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$x;
  return $x;

}
sub xorDecrypt($$) { # Ex. $plain = xorDecrypt($cipher,$key);
  #y $intent = "xor decrypt a key";
  my ($x,$k) = @_; # /!\ insecure if k smaller than d
  my @cipher = unpack'N*',$x."\0"x3;;
  my @key = (0,unpack'N*',$k."\0"x3);
  my @res = map { 0 } (0 .. $#cipher);
  my $mod = scalar(@key);
  for my $i (0 .. $#cipher) {
    $res[$i] = $cipher[$i-1] ^ $cipher[$i] ^ $key[$i % $mod];
    seclog "%d: %08X = %08X ^ %08X ^ %08X\n",$i,$res[$i],$cipher[$i-1],$cipher[$i],$key[$i % $mod] if $dbug;
  }
  shift@res;
  my $d = pack 'N*',@res;
  debug "d: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$d;
  return $d;
}

sub xorPlain { # Ex. my $res = xorPlain($a,$b);
 #y $intent = "crude bitwise Xor of strings (padded to 64bit boundary)";
 my @a = unpack'Q*',$_[0] . "\0"x7;
 my @b = unpack'Q*',$_[1] . "\0"x7;
 my @x = ();
 foreach my $i (0 .. $#a) {
   $x[$i] = $a[$i] ^ $b[$i];
   debug "%016X = %016X ^ %016X\n",$x[$i],$a[$i],$b[$i] if $dbug;
 }
 my $x = pack'Q*',@x;
}
# ------------------------------------------------
sub brokersecret {
   my $key = shift;
   my $key_raw = &decode_mbase($key);
   my $args = { @_ };
   printf "brokersecret.key: \e[33m%s\e[0m\n",$key;
   my $dhsecret;
   if (length($key_raw) > 32) {
      my $skb = $args->{broker};
      seclog "broker: %s",$skb;
      printf "brokersecret.skb: \e[31m%s\e[0m\n",$skb;
      $dhsecret = &DHSecret($skb,$key); # Shared Secret /!\
   } else {
      $dhsecret = &DHSecret($key,$pkb); # Shared Secret
      printf "brokersecret.dhsecret: \e[31m%s\e[0m\n",&encode_base64($dhsecret,'');
   }
   return $dhsecret;
}
# ------------------------------------------------
sub fprint($@) { # Ex. my $fp = &fprint($data,$privatekey);
   #y $intent = q'16B KHDH() as finger print';
   my $privdata = shift;
   my $key = shift || $privdata; # owner public|private key
   my $args = { @_ };
   seclog "key: %s\m",$key;
   #printf "--- #args: %s---\n",Dump($args);

   my $priv_raw = &decode_mbase($privdata);
   my ($dhsecret,$pko);
   my $key_raw = &decode_mbase($key);
   if (length($key_raw) > 32) {
      $pko = $key;
      my $skb = $args->{broker};
      seclog "broker: %s",$skb;
      $dhsecret = &DHSecret($skb,$key); # Shared Secret /!\
   } else {
      my $pair = ECC($key_raw);
      $pko = $pair->{public};
      $dhsecret = &DHSecret($key,$pkb); # Shared Secret
   }
   debug "dhsecret: %s",encode_base64($dhsecret,'');
   my $shortpub = substr($pko,-3);
   my $intent = "data fingerprint for $shortpub";
   my $fp_raw = &khash('SHA256',$priv_raw,$dhsecret,$intent);
   my $fp = join'-',unpack'H8H4H4H4H12',$fp_raw;
   my $obj = {
      intent => $intent,
      fp => $fp,
      pubkey => $pko,
      dhsecret => &encode_base64($dhsecret,'')

   };
   return (wantarray) ? (%$obj) : $fp;
}
sub swissnumber($@) {
   #y $intent = q'16B KHMAC-DH() as swissnumber (LUT address)';
   my ($msg,$key,$URI) = @_;
   my %args = ( @_[3..$#_] );
   my $SSN = &brokersecret($key, %args); # Share Secret
   my $sn_raw = &KHMAC('SHA256',$msg,$SSN,$URI);
   my $uuid = join'-',unpack'H8H4H4H4H12',$sn_raw;
   printf "swissnumber.uuid: \e[32m%s\e[0m\n",$uuid;
   my $SNobj = {
    uuid => $uuid,
    SSN => &encode_base64($SSN),
    key => $key,
    URI => $URI,
    value => $sn_raw,
    SN => &encode_mbase58($sn_raw)
   };
   return (wantarray) ? %$SNobj : $sn_raw;
}

# ------------------------------------------------
sub random {
  my $len = shift;
  use Crypt::Random qw( makerandom_octet );
  my $r = makerandom_octet ( Length => $len , Strength => 1, Uniform => 1 );
  #printf "random: %s\n",unpack'H*',$r;
  return $r;
}
# ------------------------------------------------
sub rand64 { # my $notsecure = rand(64);
   #y $intent = q"get a 64bit random integer /!\\ NOT Cryptographycally safe";
   my $i1 = int(rand(0xFFFF_FFFF));
   my $i2 = int(rand(0xFFFF_FFFF));
   my $q = $i1 <<32 | $i2;
   debug "i1: %08x\n",$i1 if $dbug;
   debug "i2: %08x\n",$i2 if $dbug;
   debug "rand64: 0x%s\n",unpack'H*',pack'Q',$q if $dbug;
   return $q;
}
# ------------------------------------------------
1;


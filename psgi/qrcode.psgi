#!/usr/local/bin/plackup -s Gazelle
# env SITE=$(git rev-parse --show-toplevel) plackup paladin.psgi
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

# Intent:
#   return the nid for a public key
#
# inputs:
#  /publickey


#chdir $ENV{SITE} if ( exists $ENV{SITE} && -d $ENV{SITE});
our $intent = q"get a qrcode";
my $usage = 'app/qrcode.html';

delete $ENV{CDPATH};
delete $ENV{LS_COLORS};
use YAML::XS qw(Dump);
use JSON::XS qw(encode_json);
use MIME::Base64 qw(encode_base64 decode_base64);

# // CGI compatibility :)
if ($ENV{GATEWAY_INTERFACE} eq 'CGI/1.1') {
  my @resp = $app->(\%ENV);
  print "\r\n" if $dbug;
  printf "Status: %s OK!\r\n",$resp[0];
  print join"\r\n",$resp[1];
  print "\r\n";
  print $resp[2][0];
}
# -----------------------------------------------------------------------
# PSGI application :
my $app = sub {
   my $env = shift; # PSGI env
   my $required = 'pubkey';
   my $req = Plack::Request->new($env);
   our $params = $req->parameters();
   our $uploads = $req->uploads();
   
   my $status = 200;
   my $headers = [ ];
   my $body = sprintf "--- # env %s...\n",Dump($env);
   # prepare CORS header
   if (exists $env->{HTTP_ORIGIN}) {
      printf "HTTP_ORIGIN: %s\n",$env->{HTTP_ORIGIN};
      push @$headers, 'Access-Control-Allow-Origin' => $env->{HTTP_ORIGIN};
   } else {
      push @$headers, 'Access-Control-Allow-Origin' => '*';
   }

   my $qrlink;
   use keys qw(getShard);
   if (defined $env->{PATH_INFO} && $env->{PATH_INFO} ne '' && $env->{PATH_INFO} ne '/') {
      $qrlink = substr($env->{PATH_INFO},1);
   } elsif (exists $params->{string}) {
      $qrlink = $params->{string};
      delete $params->{string};
   } elsif (exists $params->{qrlink}) {
      $qrlink = $params->{qrlink};
      delete $params->{qrlink};
   } elsif (exists $params->{url}) {
      $qrlink = $params->{url};
      delete $params->{url};
   } elsif (exists $params->{str}) {
      $qrlink = $params->{str};
      delete $params->{str};
   } elsif (exists $params->{code}) {
      $qrlink = $params->{code};
      delete $params->{code};
   } else {
      $qrlink = 'https://app.safewatch.care/'
   }
   my $qrid = &getShard($qrlink); # shard ...
   use QRcode qw(qrcode);
   my $type = $params->{type} || 'png'; $params->{type} = 'png' if (! exists $params->{type});
   my $qrimage = &qrcode($qrlink, %$params, 'format' => 'binary');
   use MIME::Base64 qw(encode_base64);
   my $mime = $params->{mime} || "image/$type";
   my $datauri = sprintf'data:%s;base64,%s',$mime,&encode_base64($qrimage,'');

   $satus = 302; # temporary moved 
   push @$headers, 'Location', $datauri;

   
   use basic qw(get_ip appendfile);
   my $ip = $params->{ip} || &get_ip($env); # /!\ user data can be pass to the log
   &appendfile('logs/qrlink.yml',sprintf qq'%s: %s %s %s\n',time,$ip,$qrid,$qrlink);

   debug("qrid: %s\n",$qrid);
   my $format = $params->{format} || $type;
   debug("format: %s\n",$format);
   debug("qrlink: %s\n",$qrlink);
   # ---------------------------------------------------------
   if ($format eq 'json') {
      # build json output
      my $resp = { qrid => $qrid, qrlink => $qrlink, qrcode => $datauri };
      # -----------------------------------------------
      push @$headers, 'Content-Type' => 'application/json';
      my $json = JSON::XS->new->canonical; # canonical : sort keys
      $body = $json->encode($resp);
      return [ $status, $headers, [ $body ]];
   } else {
      push @$headers, 'Content-Type' => "$mime";
      push @$headers, 'Content-Length' => length($qrimage);
      $body = $qrimage;
      #$status = 203; # non-authoritative
      return [ $status, $headers, [ $body ]];
   }
};
# -----------------------------------------------------------------------
# runnable ...
if (! exists $ENV{PLACK_ENV} && "$0" eq __FILE__ ) {
   printf "--- # env %s---\n",Dump(\%ENV);
   $| = 1;
   printf "--- # app %s...",Dump($app->());
} else {
  return $app;
}
# -----------------------------------------------------------------------
$app;

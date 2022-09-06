#!/usr/bin/perl
#!/usr/local/bin/plackup -s Gazelle
# env SITE=$(git rev-parse --show-toplevel) perl $SITE/psgi/mnemonic.psgi --port 5009
#  curl http://0:5009/
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

# use spot to create a secret code on the client that the server know too!
my $intent = "provide keys for a privacy";

use YAML::XS qw();
use Plack::Request qw();

delete $ENV{CDPATH};
delete $ENV{LS_COLORS};

# // CGI compatibility :)
if ($ENV{GATEWAY_INTERFACE} eq 'CGI/1.1') {
  my @resp = $app->(\%ENV);
  print "\r\n" if $dbug;
  printf "Status: %s OK!\r\n",$resp[0];
  print join"\r\n",$resp[1];
  print "\r\n";
  print $resp[2][0];
}



unless (caller) {
    require Plack::Runner;
    Plack::Runner->run(@ARGV, $0);
}

my $app = sub {
   use keys qw(getPublicKey DHSecret);
   my $env = shift; # PSGI env
   my $req = Plack::Request->new($env);
   our $params = $req->parameters();

   my $status = 200;
   my $headers = [ ];
   # prepare CORS header
   if (exists $env->{HTTP_ORIGIN}) {
      printf "HTTP_ORIGIN: %s\n",$env->{HTTP_ORIGIN};

      if ($env->{HTTP_ORIGIN} =~ /safewatch/ ) {
         $origin = $env->{HTTP_ORIGIN};
      } elsif ($env->{HTTP_ORIGIN} =~ /localhost/ ) {
         $origin = $env->{HTTP_ORIGIN};
      }
      push @$headers, 'Access-Control-Allow-Origin' => $origin;
   } else { # /!\ open to all non-originated request 
      push @$headers, 'Access-Control-Allow-Origin' => '*';
   }

   printf "REQUEST_URI: %s\n",$env->{REQUEST_URI};
   printf "SCRIPT_NAME: %s\n",$env->{SCRIPT_NAME};
   printf "PATH_INFO: %s\n",$env->{PATH_INFO};
   printf "--- # params: %s---\n",YAML::XS::Dump($params);
   my $obj;
   # -----------------------------------------------------
   if ($env->{PATH_INFO} eq '/getpublickey') {
      $obj = { getPublicKey(%$params) };
   # -----------------------------------------------------
   } elsif ($env->{PATH_INFO} eq '/dhsecret') {
      $obj = { DHSecret($params->{private},$params->{public}) };
   # -----------------------------------------------------
   } else {
      printf "SCRIPT_NAME: %s\n",$env->{SCRIPT_NAME};
      printf "PATH_INFO: %s\n",$env->{PATH_INFO};
      $status = 404;
      $obj = { 'message' => "unknown endpoint: /key/$ENV->{PATHINFO}" };
   }

   use JSON::XS qw();
   my $json = JSON::XS->new->canonical; # canonical : sort keys
   push @$headers, 'Content-Type' => 'application/json';
   #printf "headers: %s\n",YAML::XS::Dump($headers);
   return [$status,$headers,[$json->encode($obj)]];
};


$app;


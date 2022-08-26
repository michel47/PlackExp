#!/usr/local/bin/plackup -s Gazelle
# env SITE=$(git rev-parse --show-toplevel) plackup signup.psgi
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

#chdir $ENV{SITE} if ( exists $ENV{SITE} && -d $ENV{SITE});
our $intent = 'return all what you through at it';
my $usage = 'app/echo.html';

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
# -----------------------------------------------------------------------
# PSGI application :
my $app = sub {
   use YAML::XS qw(Dump);
   use JSON::XS qw(encode_json);
   #use MIME::Base64 qw(encode_base64 decode_base64);
   my $env = shift; # PSGI env
   my $req = Plack::Request->new($env);
   our $params = $req->parameters();
   our $uploads = $req->uploads();

   my $status = 200;
   my $headers = [ ];
   #printf "--- # env %s...\n",Dump($env);
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
   # -----------------------------------------------
   my $obj;
   my $e = { %$env };
   delete $e->{'psgi.errors'};
   delete $e->{'psgi.input'};
   delete $e->{'psgix.io'};
   delete $e->{'plack.request.merged'};
   delete $e->{'plack.request.upload'};

   my $obj = { request => { %$params }, uploads => { %$uploads }, env => $e };
   # -----------------------------------------------
   push @$headers, 'Content-Type' => 'application/json';
   my $json = JSON::XS->new->canonical; # canonical : sort keys
   $body = $json->encode($obj);
   return [ $status, $headers, [ $body ]];
};

sub capitalize { my $s = shift; $s =~ s/(.)/\U$1/; return $s; }
# -----------------------------------------------------------------------
if (! exists $ENV{PLACK_ENV} && "$0" eq __FILE__ ) {
   printf "--- # env %s---\n",Dump(\%ENV);
   $| = 1;
   printf "--- # app %s...",Dump($app->());
} else {
  return $app;
}
# -----------------------------------------------------------------------
$app;

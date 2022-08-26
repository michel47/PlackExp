#!/usr/bin/env plackup -s Gazelle
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

use Plack::Request;

my $app = sub { # Ex: my $resp = $app->(\%ENV);
   use keys qw(getuuid getPublicKey);
   my $env = shift;
   my $req = Plack::Request->new($env);
   my $params = $req->parameters();
   my $uuid = &getuuid($params->{seed});
   my $recipient = $params->{recipient};


   my $keypair = { &getPublicKey($uuid) };
   my $content = $keypair;
   #my $content = { 'uuid' => $uuid, 'public' => $keypair->{public} };

   my $headers = [ ];
   if (1) {
      $status = 200;
      push @$headers, 'Content-Type' => 'application/json';
      my $json = JSON::XS->new->canonical; # canonical : sort keys
      $body = $json->encode($content);
      return [ $status, $headers, [ $body ]];
   } else {
   return [200,['Content-Type'=>'text/plain'],[$uuid]];
   }
};

# vim: nu
$app; # $Source: /my/plack/applications/uuid.psgi $

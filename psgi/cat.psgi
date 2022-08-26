#!/usr/bin/env plackup -s Gazelle
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }

# echo "Project Safewatch from PaladinAI" | ipfs add --hash SHA1 --cid-base base58flickr
# $ENV{QUERY_STRING} = 'hash=Z83zJnT3mNWz1gziygr5mZjKbnMN74rgy';
#
# testing :
# . $SITE/bin/secret.sh;
# export IPFS_API_GATEWAY=https://ipfs.safewatch.care:443
# plackup -s Gazelle ../psgi/serveIpfsContent.pl
# curl -i -X GET http://0.0.0.0:5000/?hash=Z83zJnT3mNWz1gziygr5mZjKbnMN74rgy

use Plack::Request;

my $serveContentByHash = sub { # Ex: my $resp = $serveContentByHash->(\%ENV);
   use ipfs qw(ipfsapi);
   my $env = shift;
   my $req = Plack::Request->new($env);
   my $params = $req->parameters();
   printf "ipfs cat /ipfs/%s\n",$params->{hash};
   my $content = &ipfsapi('cat','arg=/ipfs/'.$params->{hash});
   return [200,['Content-Type'=>'text/plain'],[$content]];
};

# vim: nu
$serveContentByHash; # $Source: /my/plack/applications/serveIpfsContent.psgi $

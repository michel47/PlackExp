#
# Intent:
#  qrcode package 
#
# Note:
#   This work has been done during my time freelancing
#   for PaladinAI at Toptal as Doctor I·T
# 
# -- PublicDomain CC0 drit, 2021; https://creativecommons.org/publicdomain/zero/1.0/legalcode --
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
#
package QRcode;
require Exporter;
@ISA = qw(Exporter);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

use strict;
use basic qw(debug version);

our $seed = undef;

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------


sub qrcode(@) {
  use Imager::QRCode;
  my ($qr,@opt) = @_;
  my $opt = { @opt };
  my $qrcode = Imager::QRCode->new(
    size          => $opt->{size} || 2,
    margin        => $opt->{margin} || 2,
    version       => $opt->{version} || 1,
    level         => $opt->{level} || 'M',
    casesensitive => 1,
    lightcolor    => Imager::Color->new(255, 255, 255),
    darkcolor     => Imager::Color->new(1, 0, 2),
  );

  my $code;
  if ($qr =~ /^qr:/) {
    $code= substr($qr,3);
  } else {
    $code = $qr;
  }
  my $img = $qrcode->plot($code);
  my $qrdata = '';
  my $type = $opt->{type} || 'png';
  $img->write(type => $type, data => \$qrdata)
    or die "Failed to write: " . $img->errstr;

  if ($opt->{format} eq 'binary') {
    return $qrdata;
  } elsif ($opt->{format} eq 'datauri') {
    use MIME::Base64 qw(encode_base64);
    my $mime = "image/$type";
    my $datauri = sprintf'data:%s;base64,%s',$mime,&encode_base64($qrdata,'');
    return $datauri;
  } else {
    return $qrdata;
  }
}


# -----------------------------------------------------------------------
1; # $Source: /my/perl/modules/paladin.pm $

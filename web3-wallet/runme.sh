#
 SITE=$(git rev-parse --show-toplevel)
 env SITE=$SITE plackup ./app.psgi
 true; # vim: wrap


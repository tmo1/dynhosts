#!/usr/bin/env perl

# Copyright (C) 2019 Thomas More - tmore1@gmx.com
# dynhosts is free software, released under the terms of the
# Perl Artistic License 2.0, contained in the included file 'LICENSE'
# dynhosts comes with ABSOLUTELY NO WARRANTY
# The dynhosts homepage is https://github.com/tmo1/dynhosts
# dynhosts is documented in its README

use Mojolicious::Lite;
use Tie::File;
use MIME::Base64;

my ($auth_file, $hosts_file) = ('/usr/local/etc/dynhosts_auth', '/usr/local/etc/hosts');
app->log->format(sub {my ($time, $level, @lines) = @_; return "@lines\n";});
#app->log = app->log->format(sub {my ($time, $level, @lines) = @_; return "@lines\n";});
#app->log->short(1);

post '/update' => sub {
	my $c = shift;
	my ($hostname, $ip, $auth_string) = ($c->param('hostname'), $c->param('ip'), $c->req->headers->authorization);
	unless (defined $hostname && defined $ip) {return $c->render(text => "'hostname' and 'ip' must be supplied as parameters.\n\n", status => 400)}
	unless (defined $auth_string && $auth_string =~ /^\s*Basic\s+(.*)$/) {
		app->log->error("Unauthorized access from", $c->tx->remote_address, ": HTTP basic authentication credentials not present.");
		return $c->render(text => "Unauthorized!\n\n", status => 401);
	}
	my ($username, $password) = split /:/, decode_base64($1);
	unless (defined $username && defined $password) {
		app->log->error("Unauthorized access from", $c->tx->remote_address, ": no defined username / password.");
		return $c->render(text => "Unauthorized!\n\n", status => 401);
	}
	my $fh;
	unless (open $fh, "< $auth_file") {
		app->log->error("Can't open auth_file '$auth_file'.");
		return $c->render(text => "Internal error.\n\n", status => 500);
	}
	my $auth = undef;
	while (<$fh>) {if (/^\s*\Q$username\E\s+\Q$password\E\s+\Q$hostname\E\s*$/) {$auth = 1; last;}}
	unless ($auth) {
		app->log->error("Unauthorized access from", $c->tx->remote_address, ": no matching username / password / hostname triplet in '$auth_file'.");
		return $c->render(text => "Unauthorized!\n\n", status => 401);
	}
	my @hosts;
	my ($flag, $o) = (undef);
	unless ($o = tie @hosts, 'Tie::File', $hosts_file) {
		app->log->error("Failed to tie hosts file '$hosts_file'.");
		return $c->render(text => "Internal error.\n\n", status => 500);
	}
	$o->flock;
	foreach (@hosts) {if (/^\s*([^\s]+)\s+\Q$hostname\E(\s+|$)(.*)/) {$_ = "$ip\t\t$hostname$3"; $flag = 1;	last;}}
	push (@hosts, "$ip\t$hostname") unless ($flag);
	undef $o;
	unless (untie @hosts) {
		app->log->error("Failed to untie hosts file '$hosts_file'.");
		return $c->render(text => "Internal error.\n\n", status => 500);
	}
	app->log->info("Successful access from", $c->tx->remote_address, ": '$hostname' successfully set to '$ip'.");
	return $c->render(text => "'$hostname' successfully set to '$ip'\n\n", status => 200);
};

app->start;

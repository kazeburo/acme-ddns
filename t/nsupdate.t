use warnings;
use strict;
use FindBin;
use Test::More;
use Test::TCP;
use File::Temp qw/tempdir/;
use File::Which qw/which/;
use IPC::Cmd qw/run/;

my $bin = $FindBin::Bin . '/../acme-ddns';
plan skip_all => 'acme-ddns binary is not found' unless -f $bin;

my $nsupdate = which 'nsupdate';
plan skip_all => 'nsupdate binary is not found' unless defined $nsupdate;

my $dig = which 'dig';
plan skip_all => 'dig binary is not found' unless defined $dig;

my $server = Test::TCP->new(
    code => sub {
        my $port = shift;
        my @cmd = (
            $bin,
            '--zone', 'example.com',
            '--keyname', 'mykey',
            '--secret', '8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=',
            '--listen', ':'.$port
        );
        exec @cmd;
        die "cannot execute $bin: $!";
    },
);

my $port = $server->port;
my $tmpdir = tempdir( CLEANUP => 1 );
my $nsupdate_input = $tmpdir .'/server.txt';
open(my $fh, '>', $nsupdate_input) or die $!;
print $fh <<"EOF";
server 127.0.0.1 $port
zone example.com.
update delete _acme-challenge.example.com. 3600 TXT
update add _acme-challenge.example.com. 3600 TXT "BHVgrXVuoykwwgtYmzMBksiLzBBVsrfQXCG2dGkx"
send
EOF
close($fh);

{
    my( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf )= run(
        command => [$nsupdate, '-d', '-p', $port, '-y', 'hmac-sha256:mykey.:8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=', $nsupdate_input],
        timeout => 20
    );

    ok($success, 'nsupdate exit code');
    like  (join("",@$stderr_buf), qr/Reply from update query:\n.+NOERROR/, 'result with noerror');
    like  (join("",@$stderr_buf), qr/TSIG PSEUDOSECTION:\n.+NOERROR 0/, 'tsig with noerror');
}

{
    my( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf )= run(
        command => [$dig, '-p', $port, '-y', 'hmac-sha256:mykey.:i8WDMg2ieCe00dOUoCTda5cZr27M19YR+aLcaeJ0QjQ=', '+qr', '@127.0.0.1', '_acme-challenge.example.com', 'txt'],
        timeout => 20
    );
    ok($success, 'dig status with invalid tsig');
    like(join("",@$stdout_buf), qr/Couldn't verify signature: expected/, 'invalid tsig error');
}

{
    my( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf )= run(
        command => [$dig, '-p', $port, '-y', 'hmac-sha256:mykey.:8Ejc06Zhaszv50eMxm/5pce9KnjBlxI/rsokMMIhx+w=', '+qr', '@127.0.0.1', '_acme-challenge.example.com', 'txt'],
        timeout => 20
    );
    ok($success, 'dig status with invalid tsig');
    like(join("",@$stdout_buf), qr/_acme-challenge\.example\.com.\s+300\s+IN\s+TXT\s+"BHVgrXVuoykwwgtYmzMBksiLzBBVsrfQXCG2dGkx"/, 'good response');
}


done_testing;

use Test::More;
use Crypt::OpenSSL::Verify;
use Crypt::OpenSSL::X509;
use File::Slurp qw(read_file);
BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    print qq{1..0 # SKIP these tests are for testing by the author\n};
    exit
  }
}

my $v = Crypt::OpenSSL::Verify->new('t/cacert.pem');
ok($v);

my $text = read_file('t/cert-expired.pem');
like($text, qr/BhMCQ0ExFjAUBgNVBAgMDU5ldyBC/);

my $cert = Crypt::OpenSSL::X509->new_from_string($text);
ok($cert);

# Default VerifyX509 function is that expired certs are trusted
my $ret;;
eval {
        $ret = $v->verify($cert);
};
ok($@ !~ /^verify: certificate has expired/);
ok($ret);

# Verify Expired is not an error without strict_certs
$v = Crypt::OpenSSL::Verify->new(
        CAfile => 't/cacert.pem',
        CApath => '/etc/ssl/certs',
        noCApath => 0,
        npCAfile => 0,
        strict_certs => 0,
    );
ok($v);

$ret = undef;
eval {
        $ret = $v->verify($cert);
};
ok($ret);

# Verify Expired is an error with strict_certs
$v = Crypt::OpenSSL::Verify->new(
        CAfile => 't/cacert.pem',
        CApath => '/etc/ssl/certs',
        noCApath => 0,
        npCAfile => 0,
        strict_certs => 1
    );
ok($v);

$ret = undef;
eval {
        $ret = $v->verify($cert);
};
ok($@ =~ /^verify: certificate has expired/);
ok(!$ret);

done_testing;

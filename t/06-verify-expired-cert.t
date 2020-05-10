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

my $ret;;
eval {
        $ret = $v->verify($cert);
};
ok($@ =~ /^verify: certificate has expired/);
ok(!$ret);

$v = Crypt::OpenSSL::Verify->new(
    CAfile => 't/cacert.pem',
    CApath => '/etc/ssl/certs',
    noCAfile => 0,
    noStore => 0,
    );
ok($v);

my $ret = undef;
eval {
        $ret = $v->verify($cert);
};
ok($@ =~ /^verify: certificate has expired/);
ok(!$ret);

done_testing;

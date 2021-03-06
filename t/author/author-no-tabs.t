
BEGIN {
  unless ($ENV{AUTHOR_TESTING}) {
    print qq{1..0 # SKIP these tests are for testing by the author\n};
    exit
  }
}

use strict;
use warnings;

# this test was generated with Dist::Zilla::Plugin::Test::NoTabs 0.15

use Test::More 0.88;
use Test::NoTabs;

my @files = (
    'Verify.pm',
    'Verify.xs',
    't/00-basic.t',
    't/01-load-ca.t',
    't/02-verify-good-cert.t',
    't/03-verify-bad-cert.t',
    't/04-load-broken-cert.t',
    't/05-verify-not-a-cert.t',
    't/author/author-critic.t',
    't/author/author-eof.t',
    't/author/author-eol.t',
    't/author/author-no-tabs.t',
    't/author/author-pod-syntax.t',
    't/author/notabs.t',
    't/author/pod.t',
    't/author/podcoverage.t'
);

notabs_ok($_) foreach @files;
done_testing;

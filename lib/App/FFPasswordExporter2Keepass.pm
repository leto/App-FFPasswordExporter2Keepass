package App::FFPasswordExporter2Keepass;
use Moose;
with 'MooseX::Runnable';
with 'MooseX::Getopt';
use Text::CSV;
use autodie qw/:all/;
use Data::Dumper;
use English;
use 5.010;

has input => (
    isa      => 'Str',
    is       => 'ro',
    required => 1,
);

has output => (
    isa      => 'Str',
    is       => 'ro',
    required => 0,
);

has parser => (
    isa     => 'Text::CSV',
    is      => 'ro',
    default => sub { Text::CSV->new },
    metaclass => 'NoGetopt',
);
has keepass_start => (
    isa     => 'Str',
    is      => 'ro',
    default => "<!DOCTYPE KEEPASSX_DATABASE><database><group><title>Imported FF passwords at " . localtime . "</title><icon>1</icon>",
    metaclass => 'NoGetopt',
);
has keepass_end => (
    isa     => 'Str',
    is      => 'ro',
    default => "</group></database>",
    metaclass => 'NoGetopt',
);

sub run {
    my ($self) = @_;

    open my $fh, '<', $self->input;
    my $entries = '';
    my $got_header;


    while( my $line = $self->parser->getline($fh) ) {
        next if $line->[0] =~ m/^\s*#/;

        # skip header line
        unless ( $got_header ) {
            $got_header = 1;
            next;
        }

        $entries .= $self->make_keepass_entry($line);
    }

    say $self->keepass_start . $entries . $self->keepass_end;
}

sub make_keepass_entry {
    my ($self, $line) = @_;

    my ($hostname,$username,$password,$formSubmitURL,$httpRealm,$usernameField,$passwordField) = @$line;

    my $entry = <<KEEPASS_ENTRY;
  <entry>
   <title>$username @ $hostname</title>
   <username>$username</username>
   <password>$password</password>
   <url>$formSubmitURL</url>
   <comment>Realm: $httpRealm, usernameField:$usernameField, passwordField:$passwordField</comment>
   <icon>1</icon>
   <expire>Never</expire>
  </entry>
KEEPASS_ENTRY
#   <creation>$BASETIME</creation>
#   <lastaccess>$BASETIME</lastaccess>
#   <lastmod>$BASETIME</lastmod>

    return $entry;
}

1;

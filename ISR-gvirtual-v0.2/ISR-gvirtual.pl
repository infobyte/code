#!/usr/bin/perl -w

##########################################################################
# FILE       ISR-form.pl
# AUTHOR     Francisco Amato
# EMAIL      famato+at+infobyte+dot+com+dot+ar
# COMPANY    [ISR] - Infobyte Security Research
# VERSION    0.2
# DATE	     08/13/2006
##########################################################################

use strict;
use Getopt::Std;
use Net::Google;
use constant LOCAL_GOOGLE_KEY => "googlekeyapi";
use Data::Dump qw(dump);

#global variable
my $m_report="";
my @proc=('|','/','-','\\','|');

#Init Process;
&main;

##########################################################################
# FUNCTION   main
# RECEIVES   
# RETURNS
# EXPECTS
# DOES       main function
sub main {
 
    my %args;
    my $m_domain;
    my $m_sc=0;

    # Get parameter
    &getopts("l:f:o:h", \%args);

    # Set/Check commands
    if(defined $args{l}) { $m_domain = $args{l}; $m_sc++; }
    if(defined $args{o}) { $m_report = $args{o}; }
#    if(defined $args{v}) { $m_vbose=1;}
    if(defined $args{h}) { &get_usage; }
    if ($m_sc == 0 ) { print "Error: specify the domain to get gvirtual\n"; &get_usage;}

    #Log report
    &init_log("Domain name: $m_domain");;
    
    #search
    &do_search($m_domain,$m_report);
}

##########################################################################
# FUNCTION   init_log
# RECEIVES   
# RETURNS
# EXPECTS
# DOES       Initialize Log file
sub init_log
{
    my ($cmsg) = @_;
    if ($m_report ne "") {
        open (FZ,">> $m_report") || die "Error: Can't open file $m_report to save the report\n";
	my $msg= "LOG REPORT -- ISR-gvirtual.pl (*) Francisco Amato (*)  www.infobyte.com.ar\n";
	$msg.=$cmsg ."\n" if ($cmsg ne "");
	print FZ $msg;
	close(FZ);
    }
}

############################################

##########################################################################
# FUNCTION   get_usage
# RECEIVES   
# RETURNS
# EXPECTS
# DOES       help
sub get_usage
{
    print "\n-- ISR-gvirtual.pl (*) Francisco Amato (*)  www.infobyte.com.ar\n";
    print "-- Get virtual host with google engine  ----------------------------\n\n";
    print " Usage: $0 -l microsoft.com -o gvirtual.microsoft.log\n\n";
    print " <-l> domain name example: microsoft.com \n";
    print " <-o> Name of report\n";
#    print " <-v> Verbose\n";
    print " <-h> Help\n\n";
#    print "Example: $0 -l /audit/www.microsoft.com -o /audit/report.txt\n\n";
    exit;
}

##########################################################################
# FUNCTION   do_search
# RECEIVES   $domain = domain name, $log = log file
# RETURNS
# EXPECTS
# DOES       search into google engine
sub do_search {

    my ($domain,$log) = @_;
    my $google = Net::Google->new(key=>LOCAL_GOOGLE_KEY);
    my $search = $google->search();

    # Search interface
    $search->query("site:$domain");

    my $gvirtual={};
    my $c=0;
    my $j=0;
    $|=1;
    while(1) {
        $search->starts_at($c);
	$search->max_results(50);
	my $url="";
        foreach my $r (@{$search->results()}) {
    	    $url = $r->URL();
	    $url =~ /http\:\/\/([\w.\-\:]+)\/|https\:\/\/([\w.\-\:]+)\//;
	    if ($1 ne "") {
		$gvirtual->{$1}=1;
	    }else{
		$gvirtual->{$2}=1;
	    }
	}
#	print $url ."\n";
	last if ($url eq ""); #exit while 

	#var max_search
	$c=$c+50;
	
	#var proc
	if ($j==0){
	    print $proc[$j];
	}else{
    	    print "\b".$proc[$j];
	}
	$j++;
	$j = 1 if ($j==5);
		
    }
    
    if ($log ne ""){
        open (FZ,">> $log") || die "Error: Can't open file $log to save the report\n";
    }

    print "\n-- ISR-gvirtual.pl (*) Francisco Amato (*)  www.infobyte.com.ar\n";    
    foreach my $k (keys %$gvirtual){
	print $k ."\n";
	print FZ $k ."\n" if ($log);
    }
    close(FZ) if ($log);
    $|=0;
}

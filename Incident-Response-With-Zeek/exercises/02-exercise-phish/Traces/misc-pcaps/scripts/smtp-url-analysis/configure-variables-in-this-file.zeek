module SMTPurl;

#### send emails to this address
redef batch_notice_email = "";

#ignore the links seen in email
#redef link_already_seen += { "*\.example\.net\/", "*\.gro\.org\/"};

redef suspicious_file_types +=
    /\.xls$|\.pdf$|\.doc$|\.docx$|\.rar$|\.exe$|\.zip$/;

#redef ignore_file_types += /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ ;
redef ignore_file_types += /blahblhablhalblh/;
redef ignore_fp_links += /\.r87\.com\/|GALAKA\.com|support\.proofpoint\.com/;

### ignore alerts from emails originating from these subnets
### these should be ideally subnets where your mail relays are kept
### this is because we don't want bro to generate an alert for an alert its sending out
#redef ignore_mail_originators += { 1.1.1.1/24, 2.2.2.0/24} ;

redef ignore_mailfroms += /zeek@/;
redef ignore_notification_emails += { "zeek-alerts@site.org",  };

redef ignore_site_links += /example\.net\/|example\.net$|blah\.org\/|blah\.org$/
    &redef;

redef suspicious_text_in_url += /auth\.site\.org\.[a-zA-Z0-9]+(\/)?|login\.site\.orig\.[a-zA-Z0-9]+(\/)?|googledoc|googledocs|wrait\.ru/;
redef suspicious_text_in_url += /www\.foxterciaimobiliaria\.com\.br/;
redef suspicious_text_in_body += /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/;

######################### define your sites domains
##### for example example.com etc goes here
#### since regex cannot be compiled at runtime (yet) we need to define both variables
#####
redef site_domain: pattern = /aa\.test|testing\,com|example\.com/ &redef;
redef site_sub_domains: pattern =
    /.*\.(aa\.test|lbl\.gov|lbnl\.us|es\.net\.)(:[0-9]+|$)/ &redef;

######### ignore links
redef SMTPurl::ignore_fp_links +=
    /proofpoint\.com|GLAKA\.COM|groups\.google\.com\/a\/site\.org\//;

##### suspicious links
redef SMTPurl::suspicious_text_in_url += /dropbox\/proposal\//;

redef SMTPurl::suspicious_text_in_url += /\/dropbox\/index\.php|\/certificates\/dropbox|\/dropbox\/proposal\/|\/Dropbox\/dropbox|\/dropbox\/proposal|\/Dropbox\/dropbox\/|\/dropbox\/dpbx\/|\/dropbox\/dropbox\/|\/css\/dropbox\/|\/dropbox\/dropboxcont\.html|\/dropbox\/dpbx|\/db\/box\/|\/themes\/dropbox\/|\/secure-dropbox\/document\/|\/js\/dropbox\/|\/fonts\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox\/|\/dropbox\/dropbox|\/dropbox\/dpbx\/index\.php|\/countto\/dropboxjancag\/|\/certificates\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox|\/dropboxlocation\/|\/dropboxhq\/spool\/index\.php|\/dropbox\/dropbox\/dropbox\/|\/css\/dropbox/;

redef SMTPurl::suspicious_text_in_url +=
    /\/auth\/view\/share\/|\/drive\/auth\/share\//;

# dropbox phish

redef SMTPurl::suspicious_text_in_url += /new\/dropbox\/proposal\/LoginVerification\.php|new\/dropbox\/proposal\/|LoginVerification\.php/;
redef SMTPurl::suspicious_text_in_url += /auth\.login\.php|authberkeleyedu/;

############ smtp-malicious-indicators ##############
### A cron scraps various smtp related indicators from investigations
### and dumps into this file to be matched with smtp traffic no -need
### to classify indicators as sender, subject, recipient, md5 etc
### just dump all the indicators in the file below in format:
### #fields indicator<tab>description
### see: ../scripts/feeds/smtp_malicious_indicators.out for sample
### you can continue populate above file or redef one below as needed
#########################################################################

redef SMTPurl::smtp_indicator_feed = fmt(
    "%s/feeds/smtp_malicious_indicators.out", @DIR);

#redef SMTPurl::smtp_indicator_feed = "smtp_malicious_indicators.out";

################ configure what downloads to watch for #################

redef SMTPurl::watch_mime_types += /application\/x-dosexec/;

redef SMTPurl::watch_mime_types += /application\/java-archive|application\/msword|application\/pdf|application\/postscript|application\/x-7z-compressed|application\/x-bittorrent|application\/x-bzip2|application\/x-dosexec|application\/x-gzip|application\/x-hdf|application\/x-shockwave-flash|application\/x-xar|application\/x-xz|application\/zip|text\/x-php/;

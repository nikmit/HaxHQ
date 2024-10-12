drop table if exists haxhq_settings;
drop table if exists avoid_source;
drop table if exists prefer_source;
drop table if exists service_stats;
drop table if exists vuln_stats;
drop table if exists eng_stats;
drop table if exists host_notes;
drop table if exists engagement_notes;
drop table if exists http_virthost;
drop table if exists nessus_errors;
drop table if exists servicevulns;
drop table if exists csa_servicevulns;
drop table if exists findings;
drop table if exists csa_findings;
drop table if exists issues_seen;
drop table if exists services;
drop table if exists csa_reporting;
drop table if exists reporting;
drop table if exists hosts;
drop table if exists burp_scans;
drop table if exists zap_scans;
drop table if exists nessus_scans;
drop table if exists netsparker_scans;
drop table if exists scnr_scans;
drop table if exists acunetix_scans;
drop table if exists pingcastle_scans;
drop table if exists nmap_scans;
drop table if exists sitemap;
drop table if exists web;
drop table if exists user_sessions;
drop table if exists engagements;
drop table if exists users;
drop table if exists customers;
drop table if exists updates;

create table customers (
    id serial primary key,
    business_name varchar(128) unique not null,
    contact_name varchar(128),
    contact_email varchar(128),
    contact_phone varchar(32),
    pentest_template varchar(255),
    vulnscan_template varchar(255),
    audit_template varchar(255),
    licenses integer,
    mfa_required boolean default false,
    unique (business_name, contact_email)
);
create index customers_name_ind on customers(business_name);
create index customers_email_ind on customers(contact_email);

create table users (
    id serial primary key,
    nickname varchar(32) not null,
    name varchar(32),
    surname varchar(32),
    pass varchar(255),
    email varchar(128) unique not null,
    phone varchar(13),
    token char(68),
    token_time timestamp,
    user_type varchar(32) not null,
    user_group varchar(32) not null,
    admin boolean not null default false,
    customer_id smallint not null references customers on delete cascade,
    otp_secret char(32),
    colour_mode varchar(6) default 'light',
    disabled boolean default false,
    certexp date,
    certfp char(40),
    oldcertfp char(40),
    unique (nickname, customer_id)
);
create index users_group on users (user_group);
create index users_customer_id on users (customer_id);
create index users_email on users (email);

create table issues_seen (
    id serial primary key,
    title text not null,
    severity smallint,
    description text not null,
    remediation text not null,
    impact text,
    cvss real,
    cvss3 real,
    cve text,
    scanner varchar(16) not null,
    fingerprint char(64) not null,
    exploit_available boolean default false,
    exploitability_ease text,
    see_also text,
    cvss3_temporal_vector varchar(32),
    cvss_temporal_vector varchar(24),
    cvss3_vector varchar(58),
    cvss_vector char(32),
    patch_publication_date date,
    plugin_id varchar(16),
    unique (title, scanner)
);
create index issues_seen_title on issues_seen (title);
create index issues_seen_scanner on issues_seen (scanner);
create index issues_seen_severity on issues_seen (severity);

create table csa_issues_seen (
    id serial primary key,
    title text not null,
    description text not null,
    rationale text,
    impact text,
    remediation text not null,
    reference text,
    see_also text,
    policy_value text,
    scanner varchar(16),
    unique(title)
);
create index csa_issues_seen_title on csa_issues_seen (title);
create index csa_issues_seen_scanner on csa_issues_seen (scanner);

create table eng_stats (
    id serial primary key,
    engagement_hash char(64) not null,
    org_county varchar(64),
    org_type varchar(16),
    date date not null default now(),
    total_hosts integer not null,
    total_services integer not null,
    unique (engagement_hash)
);
create index eng_stats_date on eng_stats (date);
create index eng_stats_engagement_hash on eng_stats (engagement_hash);

create table vuln_stats (
    id serial primary key,
    eng_id integer references eng_stats(id) on delete cascade,    
    issue_id integer references issues_seen(id) on delete cascade,
    exposure char(8) not null,
    host_count smallint not null,
    service_count smallint not null
);
create index vuln_stats_eng_id on vuln_stats (eng_id);
create index vuln_stats_issue_id on vuln_stats (issue_id);
create index vuln_stats_exposure on vuln_stats (exposure);
create index vuln_stats_host_count on vuln_stats (host_count);
create index vuln_stats_service_count on vuln_stats (service_count);

create table service_stats (
    id serial primary key,
    vuln_id integer references vuln_stats(id) on delete cascade,
    host_hash char(64) not null,
    protocol varchar(12) not null,
    port integer not null,
    service varchar(64)
);
create index service_stats_host_hash on service_stats (host_hash);
create index service_stats_vuln_id on service_stats (vuln_id);

create table library (
    id serial primary key,
    user_id integer not null references users,
    customer_id integer not null references customers,
    source varchar(16),
    title text not null check (title <> ''),
    name varchar(255),
    severity smallint,
    orig_severity smallint,
    description text not null check (title <> ''),
    orig_description text,
    discoverability text,
    exploitability text,
    impact text,
    orig_impact text,
    remediation text not null check (title <> ''),
    orig_remediation text,
    rationale text,
    orig_rationale text,
    reference text,
    orig_reference text,
    see_also text,
    orig_see_also text,
    scanner varchar(16),
    exposure char(8) default 'external',
    cvss real,
    cvss_vector char(32),
    cvss3 real,
    cvss3_vector varchar(58),
    unique (title, exposure, user_id)
);
create index library_user_id on library (user_id);
create index library_customer_id on library (customer_id);
create index library_source on library (source);
create index library_title on library (title);
create index library_name on library (name);

create table user_sessions (
    id serial primary key,
    user_id smallint references users on delete cascade,
    ip inet not null,
    useragent text,
    start timestamp not null default now(),
    finish timestamp,
    expired boolean default false,
    authfail boolean default false
);
create index user_sessions_uid on user_sessions (user_id);
create index user_sessions_authfail on user_sessions (authfail);
create index user_sessions_expired on user_sessions (expired);

create table engagements (
    eid serial primary key,
    user_id smallint references users,
    org_name varchar(64) not null,
    target_subnets text,
    target_urls text,
    eng_start timestamp without time zone,
    eng_end timestamp without time zone,
    contact1_name varchar(64) not null,
    contact1_email varchar(64) not null,
    contact1_phone varchar(16),
    contact1_role varchar(64),
    contact2_name varchar(64),
    contact2_email varchar(64),
    contact2_phone varchar(16),
    contact2_role varchar(64),
    test_type varchar(8),
    target_type varchar(5),
    active boolean default false,
    report_done boolean default false,
    stats_exported boolean default false,
    isdummy boolean default false,
    summarised boolean default false,
    notes text
);
create index engagements_active on engagements (active);
create index engagements_uid on engagements (user_id);
create index engagements_isdummy on engagements (isdummy);

create table web (
    id serial primary key,
    engagement_id integer references engagements(eid) on delete cascade,
    url varchar(255),
    status smallint,
    redirect varchar(255),
    title varchar(255),
    cn varchar(255),
    ipv4 inet,
    ipv6 inet,
    unique (engagement_id, url)
);
create index web_eng_id on web (engagement_id);

create table nmap_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(64) not null,
    arg_string text not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index nmap_scans_eid on nmap_scans (engagement_id);
create index nmap_scans_type on nmap_scans (scan_type);

create table pingcastle_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(64) not null,
    scan_type char(8) default 'internal',
    unique (filename, engagement_id)
);
create index pingcastle_scans_ind on pingcastle_scans (engagement_id);

create table qualys_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(64) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index qualys_scans_ind on qualys_scans (engagement_id);

create table nessus_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(128) not null,
    scan_type char(8) not null,
    policy varchar(128),
    target text,
    tcp_port_range varchar(128),
    udp_port_range varchar(128),
    unscanned_closed boolean default false,
    throttle_on_congestion boolean,
    unique (filename, engagement_id)
);
create index nessus_scans_eid on nessus_scans (engagement_id);
create index nessus_scans_type on nessus_scans (scan_type);

create table netsparker_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    target varchar(128),
    date date,
    filename varchar(128) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index netsparker_scans_eid on netsparker_scans (engagement_id);

create table scnr_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    target varchar(128),
    date date,
    filename varchar(128) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index scnr_scans_eid on scnr_scans (engagement_id);

create table acunetix_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    target varchar(128),
    date date,
    filename varchar(128) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index acunetix_scans_eid on acunetix_scans (engagement_id);

create table burp_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(64) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index burp_scans_eid on burp_scans (engagement_id);

create table zap_scans (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    filename varchar(64) not null,
    scan_type char(8) not null,
    unique (filename, engagement_id)
);
create index zap_scans_eid on zap_scans (engagement_id);

create table hosts (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    ipv4 inet,
    ipv6 inet,
    os text,
    fqdn varchar(128),
    rdns varchar(128),
    notes text,
    unique (ipv4, engagement_id),
    unique (ipv6, engagement_id),
    check (ipv4 is not null or ipv6 is not null)
);
create index hosts_eid on hosts (engagement_id);
create index hosts_ipv4 on hosts (ipv4);
create index hosts_os on hosts (os);
create index hosts_fqdn on hosts (fqdn);

create table reporting (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    title text not null,
    name text,
    severity smallint not null,
    description text,
    discoverability text,
    exploitability text,
    impact text,
    remediation text,
    picture1 varchar(64),
    picture2 varchar(64),
    ready boolean not null default false,
    cvss real,
    cvss3 real,
    cvss_vector char(32),
    cvss3_vector varchar(58),
    cve text,
    exposure char(8) not null,
    ce_impact varchar(6),
    proof text,
    deleted boolean default false,
    merged_with integer references reporting(id),
    autoupdated boolean not null default false,
    scanner varchar(16),
    details text,
    unique (engagement_id, title, exposure)
);
create index reporting_eid on reporting (engagement_id);
create index reporting_title on reporting (title);
create index reporting_severity on reporting (severity);
create index reporting_ready on reporting (ready);
create index reporting_merged_with on reporting (merged_with);
create index reporting_deleted on reporting (deleted);

create table csa_reporting (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    title text not null,
    name text,
    compliance varchar(16) not null,
    description text,
    rationale text,
    impact text,
    remediation text,
    reference text,
    ready boolean not null default false,
    deleted boolean default false, 
    merged_with integer references csa_reporting(id) on delete set null,
    audit_level char(2),
    control_set char(2),
    benchmark varchar(128),
    audit_file varchar(128),
    service_name varchar(128),
    autoupdated varchar(16),
    unique (engagement_id, title)
);
create index csa_reporting_eid on csa_reporting (engagement_id);
create index csa_reporting_title on csa_reporting (title);
create index csa_reporting_compl on csa_reporting (compliance);
create index csa_reporting_ready on csa_reporting (ready);
create index csa_reporting_merged_with on csa_reporting (merged_with);

create table services (
    id serial primary key,
    host_id integer not null references hosts(id) on delete cascade,
    protocol varchar(12),
    port integer,
    service varchar(64),
    software text,
    cert_cn text,
    sitemap text,
    web_dir_enum text,
    no404sent boolean default false,
    cgi_enum text,
    robots_txt text,
    injectable_param text,
    sensitive_param text,
    php_version varchar(256),
    phpmyadmin  text,
    drupal_detected text,
    wordpress_detected text,
    python_detected text,
    dotnet_handlers text,
    embedded_server boolean default false,
    software_favicon varchar(256),
    external boolean not null default false,
    webappurl varchar(255),
    scan_uri_list varchar(255) not null,
    unique (host_id, protocol, port, webappurl)
);
create index services_host_id on services (host_id);
create index services_protocol on services (protocol);
create index services_port on services (port);

create table findings (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    service_id integer not null references services(id) on delete cascade,
    issue_id integer not null references issues_seen,
    external boolean,
    proof text,
    request text,
    plugin_output text,
    notes text,
    vhost varchar(255),
    scan_uri_list varchar(255) not null
);
create index findings_eid on findings (engagement_id);
create index findings_sid on findings (service_id);
create index findings_issue_id on findings (issue_id);


create table csa_findings (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    service_id integer not null references services(id) on delete cascade,
    issue_id integer not null references issues_seen,
    plugin_output text,
    compliance varchar(16),
    audit_level varchar(32),
    control_set varchar(32),
    benchmark varchar(128) not null,
    audit_file varchar(128),
    service_name varchar(128),
    actual_value text,
    nessus_id integer references nessus_scans(id) on delete cascade,
    pingcastle_id integer references pingcastle_scans(id) on delete cascade
);
create index csa_findings_eid on csa_findings (engagement_id);
create index csa_findings_sid on csa_findings (service_id);
create index csa_findings_issue_id on csa_findings (issue_id);
create index csa_findings_compl on csa_findings (compliance);
create index csa_findings_nessus on csa_findings (nessus_id);
create index csa_findings_pingcastle on csa_findings (pingcastle_id);

create table nessus_errors (
    id serial primary key,
    service_id integer not null references services(id) on delete cascade,
    error_text text not null
);
create index nessus_errors_ind on nessus_errors (service_id);

create table servicevulns (
    id serial primary key,
    service_id integer not null references services(id) on delete cascade,
    report_vuln_id integer not null references reporting(id) on delete cascade,
    finding_id integer references findings on delete cascade
);
create index servicevulns_sid on servicevulns (service_id);
create index servicevulns_vuln_id on servicevulns (report_vuln_id);
create index servicevulns_fid on servicevulns (finding_id);

create table csa_servicevulns (
    id serial primary key,
    service_id integer not null references services on delete cascade,
    report_vuln_id integer not null references csa_reporting on delete cascade,
    finding_id integer not null references csa_findings on delete cascade
);
create index csa_servicevulns_sid on csa_servicevulns (service_id);
create index csa_servicevulns_vuln_id on csa_servicevulns (report_vuln_id);
create index csa_servicevulns_fid on csa_servicevulns (finding_id);

create table http_virthost (
    id serial primary key,
    host_id integer not null references hosts(id) on delete cascade,
    virthost text not null,
    unique (host_id, virthost)
);
create index http_virthost_host_id on http_virthost (host_id);

create table pingcastle_config (
    id serial primary key,
    title varchar(255),
    var_name varchar(32),
    var_label varchar(128)
);
create index pingcastle_config_ind on pingcastle_config (title);

--unused
create table sitemap (
    id serial primary key,
    web_id integer references web(id) on delete cascade,
    page varchar(255) not null,
    unique (web_id, page)
);

create table engagement_notes (
    id serial primary key,
    engagement_id integer not null references engagements(eid) on delete cascade,
    note text not null
);
create index engagement_notes_ind on engagement_notes (engagement_id);

create table host_notes (
    id serial primary key,
    host_id integer not null references hosts(id) on delete cascade,
    note text not null
);

create table prefer_source (
    id serial primary key,
    title varchar(255) unique not null,
    source varchar(16) not null
);

create table avoid_source (
    id serial primary key,
    title varchar(255) unique not null,
    source varchar(16) not null,
    override1 smallint references prefer_source,
    override2 smallint references prefer_source
);
create index avoid_source_ind on avoid_source (title, source);

create table updates (
    id serial primary key,
    update_type varchar(16),
    time_checked timestamp not null default now(),
    upgradable text not null,
    installed boolean default false
);
create index updates_ind on updates(time_checked, installed);

create table haxhq_settings (
  login_logo_src varchar(255),
  login_logo_width int,
  login_logo_height int
);
insert into haxhq_settings (login_logo_src, login_logo_width, login_logo_height) values ('/static/img/logo_white.png', 160, 65);

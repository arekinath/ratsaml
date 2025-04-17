%%
%% ratsaml
%%
%% Copyright 2022, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

%% @private
-module(ratsaml_core).

-include_lib("xmlrat/include/records.hrl").
-compile({parse_transform, xmlrat_parse_transform}).

-export([
    gen_assertion/1,
    gen_assertion/2,
    gen_attribute/1,
    gen_attribute/2,
    gen_attr_metadata/1,
    gen_attr_metadata/2,
    gen_attr_req/1,
    gen_attr_req/2,
    gen_attr_reqs/1,
    gen_attr_reqs/2,
    gen_authn_context/1,
    gen_authn_context/2,
    gen_authn_metadata/1,
    gen_authn_metadata/2,
    gen_authn_request/1,
    gen_authn_request/2,
    gen_authn_stmt/1,
    gen_authn_stmt/2,
    gen_conditions/1,
    gen_conditions/2,
    gen_contact/1,
    gen_contact/2,
    gen_endpoint/1,
    gen_endpoint/2,
    gen_idp_metadata/1,
    gen_idp_metadata/2,
    gen_intl_string/1,
    gen_intl_string/2,
    gen_issuer/1,
    gen_issuer/2,
    gen_key_info/1,
    gen_key_info/2,
    gen_logout_request/1,
    gen_logout_request/2,
    gen_logout_response/1,
    gen_logout_response/2,
    gen_metadata/1,
    gen_metadata/2,
    gen_name_id/1,
    gen_name_id/2,
    gen_name_id_policy/1,
    gen_name_id_policy/2,
    gen_organization/1,
    gen_organization/2,
    gen_pdp_metadata/1,
    gen_pdp_metadata/2,
    gen_req_authn_context/1,
    gen_req_authn_context/2,
    gen_response/1,
    gen_response/2,
    gen_sp_metadata/1,
    gen_sp_metadata/2,
    gen_status/1,
    gen_status/2,
    gen_subj_confirmation/1,
    gen_subj_confirmation/2,
    gen_subject/1,
    gen_subject/2,
    gen_subj_locality/1,
    gen_subj_locality/2,
    gen_ui_logo/1,
    gen_ui_logo/2,
    gen_ui_metadata/1,
    gen_ui_metadata/2,
    match_assertion/1,
    match_attribute/1,
    match_attr_metadata/1,
    match_attr_req/1,
    match_attr_reqs/1,
    match_authn_context/1,
    match_authn_metadata/1,
    match_authn_request/1,
    match_authn_stmt/1,
    match_conditions/1,
    match_contact/1,
    match_endpoint/1,
    match_idp_metadata/1,
    match_intl_string/1,
    match_issuer/1,
    match_key_info/1,
    match_logout_request/1,
    match_logout_response/1,
    match_metadata/1,
    match_name_id/1,
    match_name_id_policy/1,
    match_organization/1,
    match_pdp_metadata/1,
    match_req_authn_context/1,
    match_response/1,
    match_sp_metadata/1,
    match_status/1,
    match_subj_confirmation/1,
    match_subject/1,
    match_subj_locality/1,
    match_ui_logo/1,
    match_ui_metadata/1
    ]).

-include_lib("ratsaml/include/records.hrl").

-define(NS, #{
    <<"saml">> => ?NS_saml,
    <<"samlp">> => ?NS_samlp,
    <<"md">> => ?NS_md,
    <<"mdui">> => ?NS_mdui,
    <<"ds">> => ?NS_dsig
    }).

-xpath_record({match_name_id, saml_name_id, #{
    name_qualifier => "/saml:NameID/@NameQualifier",
    sp_name_qualifier => "/saml:NameID/@SPNameQualifier",
    format => "/saml:NameID/@Format",
    sp_provided_id => "/saml:NameID/@SPProvidedID",
    name => "/saml:NameID/text()"
    }, ?NS}).
-xml_record({gen_name_id, saml_name_id,
    "<saml:NameID "
        "NameQualifier='&name_qualifier;' "
        "SPNameQualifier='&sp_name_qualifier;' "
        "Format='&format;' "
        "SPProvidedID='&sp_provided_id;'>"
        "&name;"
    "</saml:NameID>", ?NS}).

-xpath_record({match_issuer, saml_issuer, #{
    name_qualifier => "/saml:Issuer/@NameQualifier",
    sp_name_qualifier => "/saml:Issuer/@SPNameQualifier",
    format => "/saml:Issuer/@Format",
    sp_provided_id => "/saml:Issuer/@SPProvidedID",
    name => "/saml:Issuer/text()"
    }, ?NS}).
-xml_record({gen_issuer, saml_issuer,
    "<saml:Issuer "
        "NameQualifier='&name_qualifier;' "
        "SPNameQualifier='&sp_name_qualifier;' "
        "Format='&format;' "
        "SPProvidedID='&sp_provided_id;'>"
        "&name;"
    "</saml:Issuer>", ?NS}).

-xpath_record({match_subj_confirmation, saml_subj_confirmation, #{
    method => "/saml:SubjectConfirmation/@Method",
    name => "/saml:SubjectConfirmation/saml:NameId",
    not_before => "/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotBefore",
    not_on_or_after => "/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter",
    recipient => "/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient",
    in_response_to => "/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo",
    address => "/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Address"
    }, ?NS}).
-xml_record({gen_subj_confirmation, saml_subj_confirmation,
    "<saml:SubjectConfirmation Method='&method;'>"
        "&name;"
        "<saml:SubjectConfirmationData "
            "NotBefore='&not_before;' "
            "NotOnOrAfter='&not_on_or_after;' "
            "Recipient='&recipient;' "
            "InResponseTo='&in_response_to;' "
            "Address='&address;' />"
    "</saml:SubjectConfirmation>", ?NS}).

-xpath_record({match_subject, saml_subject, #{
    name => "/saml:Subject/saml:NameID",
    confirmations => "/saml:Subject/saml:SubjectConfirmation"
    }, ?NS}).
-xml_record({gen_subject, saml_subject,
    "<saml:Subject>"
        "&name;"
        "&confirmations;"
    "</saml:Subject>", ?NS}).

-xpath_record({match_conditions, saml_conditions, #{
    not_before => "/saml:Conditions/@NotBefore",
    not_on_or_after => "/saml:Conditions/@NotOnOrAfter",
    one_time_use => "/saml:Conditions/saml:OneTimeUse",
    audiences => "/saml:Conditions/saml:AudienceRestriction/saml:Audience"
    }, ?NS}).
-xml_record({gen_conditions, saml_conditions,
    "<saml:Conditions "
        "NotBefore='&not_before;' "
        "NotOnOrAfter='&not_on_or_after;'>"
        "<mxsl:if true='one_time_use'>"
            "<saml:OneTimeUse />"
        "</mxsl:if>"
        "<mxsl:if defined='audiences'>"
            "<saml:AudienceRestriction>"
                "<mxsl:for-each field='audiences' as='x'>"
                    "<saml:Audience>&x;</saml:Audience>"
                "</mxsl:for-each>"
            "</saml:AudienceRestriction>"
        "</mxsl:if>"
    "</saml:Conditions>", ?NS}).

-xpath_record({match_subj_locality, saml_subj_locality, #{
    address => "/saml:SubjectLocality/@Address",
    dns_name => "/saml:SubjectLocality/@DNSName"
    }, ?NS}).
-xml_record({gen_subj_locality, saml_subj_locality,
    "<saml:SubjectLocality "
        "Address='&address;' "
        "DNSName='&dns_name;' />", ?NS}).

-xpath_record({match_authn_context, saml_authn_context, #{
    class_ref => "/saml:AuthnContext/saml:AuthnContextClassRef/text()",
    authorities => "/saml:AuthnContext/saml:AuthenticatingAuthority"
    }, ?NS}).
-xml_record({gen_authn_context, saml_authn_context,
    "<saml:AuthnContext>"
        "<saml:AuthnContextClassRef>&class_ref;</saml:AuthnContextClassRef>"
        "<mxsl:for-each field='authorities' as='x'>"
            "<saml:AuthenticatingAuthority>&x;</saml:AuthenticatingAuthority>"
        "</mxsl:for-each>"
    "</saml:AuthnContext>", ?NS}).

-xpath_record({match_authn_stmt, saml_authn_stmt, #{
    authn_instant => "/saml:AuthnStatement/@AuthnInstant",
    session_index => "/saml:AuthnStatement/@SessionIndex",
    session_not_on_or_after => "/saml:AuthnStatement/@SessionNotOnOrAfter",
    locality => "/saml:AuthnStatement/saml:SubjectLocality",
    context => "/saml:AuthnStatement/saml:AuthnContext"
    }, ?NS}).
-xml_record({gen_authn_stmt, saml_authn_stmt,
    "<saml:AuthnStatement "
        "AuthnInstant='&authn_instant;' "
        "SessionIndex='&session_index;' "
        "SessionNotOnOrAfter='&session_not_on_or_after;'>"
        "&locality;"
        "&context;"
    "</saml:AuthnStatement>", ?NS}).

-xpath_record({match_attribute, saml_attribute, #{
    name => "/saml:Attribute/@Name",
    name_format => "/saml:Attribute/@NameFormat",
    friendly_name => "/saml:Attribute/@FriendlyName",
    values => "/saml:Attribute/saml:AttributeValue"
    }, ?NS}).
-xml_record({gen_attribute, saml_attribute,
    "<saml:Attribute "
        "Name='&name;' "
        "NameFormat='&name_format;' "
        "FriendlyName='&friendly_name;'>"
        "<mxsl:for-each field='values' as='x'>"
            "<saml:AttributeValue>&x;</saml:AttributeValue>"
        "</mxsl:for-each>"
    "</saml:Attribute>", ?NS}).

-xpath_record({match_assertion, saml_assertion, #{
    version => "/saml:Assertion/@Version",
    id => "/saml:Assertion/@ID",
    issue_instant => "/saml:Assertion/@IssueInstant",
    issuer => "/saml:Assertion/saml:Issuer",
    subject => "/saml:Assertion/saml:Subject",
    conditions => "/saml:Assertion/saml:Conditions",
    authn_stmt => "/saml:Assertion/saml:AuthnStatement",
    attributes => "/saml:Assertion/saml:AttributeStatement/saml:Attribute"
    }, ?NS}).
-xml_record({gen_assertion, saml_assertion,
    "<saml:Assertion Version='&version;' ID='&id;' "
        "IssueInstant='&issue_instant;'>"
        "&issuer;"
        "&subject;"
        "&conditions;"
        "&authn_stmt;"
        "<mxsl:if defined='attributes'>"
            "<saml:AttributeStatement>"
                "&attributes;"
            "</saml:AttributeStatement>"
        "</mxsl:if>"
    "</saml:Assertion>", ?NS}).

-xpath_record({match_status, saml_status, #{
    code => "/samlp:Status/samlp:StatusCode/@Value",
    sub_code => "/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value",
    message => "/samlp:Status/samlp:StatusMessage/text()"
    }, ?NS}).
-xml_record({gen_status, saml_status,
    "<samlp:Status>"
        "<samlp:StatusCode Value='&code;'>"
            "<mxsl:if defined='sub_code'>"
                "<samlp:StatusCode Value='&sub_code;' />"
            "</mxsl:if>"
        "</samlp:StatusCode>"
        "<samlp:StatusMessage>&message;</samlp:StatusMessage>"
    "</samlp:Status>", ?NS}).

-xpath_record({match_response, saml_response, #{
    version => "/samlp:Response/@Version",
    id => "/samlp:Response/@ID",
    issue_instant => "/samlp:Response/@IssueInstant",
    in_response_to => "/samlp:Response/@InResponseTo",
    destination => "/samlp:Response/@Destination",
    consent => "/samlp:Response/@Consent",
    issuer => "/samlp:Response/saml:Issuer",
    status => "/samlp:Response/samlp:Status",
    assertions => "/samlp:Response/saml:Assertion"
    }, ?NS}).
-xml_record({gen_response, saml_response,
    "<samlp:Response Version='&version;' ID='&id;' "
        "IssueInstant='&issue_instant;' "
        "InResponseTo='&in_response_to;' "
        "Destination='&destination;' "
        "Consent='&consent;'>"
        "&issuer;"
        "&status;"
        "&assertions;"
    "</samlp:Response>", ?NS}).

-xpath_record({match_req_authn_context, saml_req_authn_context, #{
    class_ref => "/samlp:RequestedAuthnContext/saml:AuthnContextClassRef/text()",
    comparison => "/samlp:RequestedAuthnContext/@Comparison"
    }, ?NS}).
-xml_record({gen_req_authn_context, saml_req_authn_context,
    "<samlp:RequestedAuthnContext Comparison='&comparison;'>"
        "<mxsl:if defined='class_ref'>"
            "<saml:AuthnContextClassRef>&class_ref;</saml:AuthnContextClassRef>"
        "</mxsl:if>"
    "</samlp:RequestedAuthnContext>", ?NS}).

-xpath_record({match_name_id_policy, saml_name_id_policy, #{
    format => "/samlp:NameIDPolicy/@Format",
    sp_name_qualifier => "/samlp:NameIDPolicy/@SPNameQualifier",
    allow_create => "/samlp:NameIDPolicy/@AllowCreate"
    }, ?NS}).
-xml_record({gen_name_id_policy, saml_name_id_policy,
    "<samlp:NameIDPolicy Format='&format;' "
        "SPNameQualifier='&sp_name_qualifier;'>"
        "<mxsl:if true='allow_create'>"
            "<mxsl:attribute name='AllowCreate'>true</mxsl:attribute>"
        "</mxsl:if>"
    "</samlp:NameIDPolicy>", ?NS}).

-xpath_record({match_authn_request, saml_authn_request, #{
    version => "/samlp:AuthnRequest/@Version",
    id => "/samlp:AuthnRequest/@ID",
    issue_instant => "/samlp:AuthnRequest/@IssueInstant",
    destination => "/samlp:AuthnRequest/@Destination",
    consent => "/samlp:AuthnRequest/@Consent",
    issuer => "/samlp:AuthnRequest/saml:Issuer",
    subject => "/samlp:AuthnRequest/saml:Subject",
    name_id_policy => "/samlp:AuthnRequest/samlp:NameIDPolicy",
    conditions => "/samlp:AuthnRequest/saml:Conditions",
    context => "/samlp:AuthnRequest/samlp:RequestedAuthnContext",
    force_authn => "/samlp:AuthnRequest/@ForceAuthn",
    passive => "/samlp:AuthnRequest/@IsPassive",
    assertion_svc_index => "/samlp:AuthnRequest/@AssertionConsumerServiceIndex",
    assertion_svc_url => "/samlp:AuthnRequest/@AssertionConsumerServiceURL",
    attribute_svc_index => "/samlp:AuthnRequest/@AttributeConsumingServiceIndex",
    binding => "/samlp:AuthnRequest/@ProtocolBinding",
    provider_name => "/samlp:AuthnRequest/@ProviderName"
    }, ?NS}).
-xml_record({gen_authn_request, saml_authn_request,
    "<samlp:AuthnRequest Version='&version;' ID='&id;' "
        "IssueInstant='&issue_instant;' "
        "Destination='&destination;' "
        "Consent='&consent;' "
        "AssertionConsumerServiceIndex='&assertion_svc_index;' "
        "AssertionConsumerServiceURL='&assertion_svc_url;' "
        "AttributeConsumingServiceIndex='&attribute_svc_index;' "
        "ProtocolBinding='&binding;' "
        "ProviderName='&provider_name;'>"
        "<mxsl:if true='force_authn'>"
            "<mxsl:attribute name='ForceAuthn'>true</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:if true='passive'>"
            "<mxsl:attribute name='IsPassive'>true</mxsl:attribute>"
        "</mxsl:if>"
        "&issuer;"
        "&subject;"
        "&name_id_policy;"
        "&conditions;"
        "&context;"
    "</samlp:AuthnRequest>", ?NS}).

-xpath_record({match_logout_request, saml_logout_request, #{
    version => "/samlp:LogoutRequest/@Version",
    id => "/samlp:LogoutRequest/@ID",
    issue_instant => "/samlp:LogoutRequest/@IssueInstant",
    destination => "/samlp:LogoutRequest/@Destination",
    consent => "/samlp:LogoutRequest/@Consent",
    issuer => "/samlp:LogoutRequest/saml:Issuer",
    not_on_or_after => "/samlp:LogoutRequest/@NotOnOrAfter",
    reason => "/samlp:LogoutRequest/@Reason",
    name_id => "/samlp:LogoutRequest/saml:NameID",
    session_indexes => "/samlp:LogoutRequest/samlp:SessionIndex"
    }, ?NS}).
-xml_record({gen_logout_request, saml_logout_request,
    "<samlp:LogoutRequest Version='&version;' ID='&id;' "
        "IssueInstant='&issue_instant;' "
        "Destination='&destination;' "
        "Consent='&consent;' "
        "NotOnOrAfter='&not_on_or_after;' "
        "Reason='&reason;'>"
        "&issuer;"
        "&name_id;"
        "<mxsl:for-each field='session_indexes' as='x'>"
            "<samlp:SessionIndex>&x;</samlp:SessionIndex>"
        "</mxsl:for-each>"
    "</samlp:LogoutRequest>", ?NS}).

-xpath_record({match_logout_response, saml_logout_response, #{
    version => "/samlp:LogoutResponse/@Version",
    id => "/samlp:LogoutResponse/@ID",
    issue_instant => "/samlp:LogoutResponse/@IssueInstant",
    in_response_to => "/samlp:LogoutResponse/@InResponseTo",
    destination => "/samlp:LogoutResponse/@Destination",
    consent => "/samlp:LogoutResponse/@Consent",
    issuer => "/samlp:LogoutResponse/saml:Issuer",
    status => "/samlp:LogoutResponse/samlp:Status"
    }, ?NS}).
-xml_record({gen_logout_response, saml_logout_response,
    "<samlp:LogoutResponse Version='&version;' ID='&id;' "
        "IssueInstant='&issue_instant;' "
        "InResponseTo='&in_response_to;' "
        "Destination='&destination;' "
        "Consent='&consent;'>"
        "&issuer;"
        "&status;"
    "</samlp:LogoutResponse>", ?NS}).

-xpath_record({match_intl_string, saml_intl_string, #{
    tag => "/*/name()",
    lang => "/*/@xml:lang",
    value => "/*/text()"
    }, ?NS}).
-xml_record({gen_intl_string, saml_intl_string,
    "<mxsl:tag mxsl:field='tag' xml:lang='&lang;'>"
        "&value;"
    "</mxsl:tag>", ?NS}).

-xpath_record({match_ui_logo, saml_ui_logo, #{
    lang => "/mdui:Logo/@xml:lang",
    height => "/mdui:Logo/@height",
    width => "/mdui:Logo/@width",
    url => "/mdui:Logo/text()"
    }, ?NS}).
-xml_record({gen_ui_logo, saml_ui_logo,
    "<mdui:Logo xml:lang='&lang;' "
        "height='&height;' "
        "width='&width;'>"
        "&url;"
    "</mdui:Logo>", ?NS}).

-xpath_record({match_ui_metadata, saml_ui_metadata, #{
    display_names => "/mdui:UIInfo/mdui:DisplayName",
    descriptions => "/mdui:UIInfo/mdui:Description",
    keywords => "/mdui:UIInfo/mdui:Keywords",
    logos => "/mdui:UIInfo/mdui:Logo",
    info_urls => "/mdui:UIInfo/mdui:InformationURL",
    privacy_urls => "/mdui:UIInfo/mdui:PrivacyStatementURL"
    }, ?NS}).
-xml_record({gen_ui_metadata, saml_ui_metadata,
    "<mdui:UIInfo>"
        "&display_names;"
        "&descriptions;"
        "&keywords;"
        "&logos;"
        "&info_urls;"
        "&privacy_urls;"
    "</mdui:UIInfo>", ?NS}).

-xpath_record({match_endpoint, saml_endpoint, #{
    tag => "/*/name()",
    binding => "/*/@Binding",
    location => "/*/@Location",
    response_location => "/*/@ResponseLocation",
    index => "/*/@index",
    default => "/*/@isDefault"
    }, ?NS}).
-xml_record({gen_endpoint, saml_endpoint,
    "<mxsl:tag mxsl:field='tag'>"
        "<mxsl:attribute name='Binding'>&binding;</mxsl:attribute>"
        "<mxsl:attribute name='Location'>&location;</mxsl:attribute>"
        "<mxsl:if defined='response_location'>"
            "<mxsl:attribute name='ResponseLocation'>&response_location;</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:if defined='index'>"
            "<mxsl:attribute name='index'>&index;</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:if true='default'>"
            "<mxsl:attribute name='isDefault'>true</mxsl:attribute>"
        "</mxsl:if>"
    "</mxsl:tag>", ?NS}).

-xpath_record({match_organization, saml_organization, #{
    name => "/md:Organization/md:OrganizationName",
    display_name => "/md:Organization/md:OrganizationDisplayName",
    url => "/md:Organization/md:OrganizationURL"
    }, ?NS}).
-xml_record({gen_organization, saml_organization,
    "<md:Organization>"
        "&name;"
        "&display_name;"
        "&url;"
    "</md:Organization>", ?NS}).

-xpath_record({match_contact, saml_contact, #{
    type => "/md:ContactPerson/@contactType",
    company => "/md:ContactPerson/md:Company/text()",
    given_name => "/md:ContactPerson/md:GivenName/text()",
    surname => "/md:ContactPerson/md:SurName/text()",
    email => "/md:ContactPerson/md:EmailAddress",
    phone => "/md:ContactPerson/md:TelephoneNumber"
    }, ?NS}).
-xml_record({gen_contact, saml_contact,
    "<md:ContactPerson contactType='&type;'>"
        "<md:Company>&company;</md:Company>"
        "<md:GivenName>&given_name;</md:GivenName>"
        "<md:SurName>&surname;</md:SurName>"
        "<mxsl:for-each field='email' as='x'>"
            "<md:EmailAddress>&x;</md:EmailAddress>"
        "</mxsl:for-each>"
        "<mxsl:for-each field='phone' as='x'>"
            "<md:TelephoneNumber>&x;</md:TelephoneNumber>"
        "</mxsl:for-each>"
    "</md:ContactPerson>", ?NS}).

-xpath_record({match_key_info, saml_key_info, #{
    use => "/md:KeyDescriptor/@use",
    info => "/md:KeyDescriptor/ds:KeyInfo"
    }, ?NS}).
-xml_record({gen_key_info, saml_key_info,
    "<md:KeyDescriptor use='&use;'>"
        "&info;"
    "</md:KeyDescriptor>", ?NS}).

-xpath_record({match_attr_req, saml_attr_req, #{
    name => "/md:RequestedAttribute/@Name",
    name_format => "/md:RequestedAttribute/@NameFormat",
    friendly_name => "/md:RequestedAttribute/@FriendlyName",
    values => "/md:RequestedAttribute/saml:AttributeValue",
    required => "/md:RequestedAttribute/@isRequired"
    }, ?NS}).
-xml_record({gen_attr_req, saml_attr_req,
    "<md:RequestedAttribute "
        "Name='&name;' "
        "NameFormat='&name_format;' "
        "FriendlyName='&friendly_name;'>"
        "<mxsl:if true='required'>"
            "<mxsl:attribute name='isRequired'>true</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:for-each field='values' as='x'>"
            "<saml:AttributeValue>&x;</saml:AttributeValue>"
        "</mxsl:for-each>"
    "</md:RequestedAttribute>", ?NS}).

-xpath_record({match_authn_metadata, saml_authn_metadata, #{
    id => "/md:AuthnAuthorityDescriptor/@ID",
    valid_until => "/md:AuthnAuthorityDescriptor/@validUntil",
    cache_duration => "/md:AuthnAuthorityDescriptor/@cacheDuration",
    protocols => "/md:AuthnAuthorityDescriptor/@protocolSupportEnumeration",
    error_url => "/md:AuthnAuthorityDescriptor/@errorURL",
    keys => "/md:AuthnAuthorityDescriptor/md:KeyDescriptor",
    organization => "/md:AuthnAuthorityDescriptor/md:Organization",
    contacts => "/md:AuthnAuthorityDescriptor/md:ContactPerson",
    name_id_formats => "/md:AuthnAuthorityDescriptor/md:NameIDFormat",
    authn_query => "/md:AuthnAuthorityDescriptor/md:AuthzService",
    assertion_id_req => "/md:AuthnAuthorityDescriptor/md:AssertionIDRequestService"
    }, ?NS}).
-xml_record({gen_authn_metadata, saml_authn_metadata,
    "<md:AuthnAuthorityDescriptor "
        "ID='&id;' validUntil='&valid_until;' cacheDuration='&cache_duration;' "
        "protocolSupportEnumeration='&protocols;' "
        "errorURL='&error_url;'>"
        "&keys;"
        "&organization;"
        "&contacts;"
        "&name_id_formats;"
        "&authn_query;"
        "&assertion_id_req;"
    "</md:AuthnAuthorityDescriptor>", ?NS}).

-xpath_record({match_attr_metadata, saml_attr_metadata, #{
    id => "/md:AttributeAuthorityDescriptor/@ID",
    valid_until => "/md:AttributeAuthorityDescriptor/@validUntil",
    cache_duration => "/md:AttributeAuthorityDescriptor/@cacheDuration",
    protocols => "/md:AttributeAuthorityDescriptor/@protocolSupportEnumeration",
    error_url => "/md:AttributeAuthorityDescriptor/@errorURL",
    keys => "/md:AttributeAuthorityDescriptor/md:KeyDescriptor",
    organization => "/md:AttributeAuthorityDescriptor/md:Organization",
    contacts => "/md:AttributeAuthorityDescriptor/md:ContactPerson",
    name_id_formats => "/md:AttributeAuthorityDescriptor/md:NameIDFormat",
    profiles => "/md:AttributeAuthorityDescriptor/md:AttributeProfile",
    attrs => "/md:AttributeAuthorityDescriptor/saml:Attribute",
    attr_query => "/md:AttributeAuthorityDescriptor/md:AttributeService",
    assertion_id_req => "/md:AttributeAuthorityDescriptor/md:AssertionIDRequestService"
    }, ?NS}).
-xml_record({gen_attr_metadata, saml_attr_metadata,
    "<md:AttributeAuthorityDescriptor "
        "ID='&id;' validUntil='&valid_until;' cacheDuration='&cache_duration;' "
        "protocolSupportEnumeration='&protocols;' "
        "errorURL='&error_url;'>"
        "&keys;"
        "&organization;"
        "&contacts;"
        "&name_id_formats;"
        "&profiles;"
        "&attrs;"
        "&attr_query;"
        "&assertion_id_req;"
    "</md:AttributeAuthorityDescriptor>", ?NS}).

-xpath_record({match_pdp_metadata, saml_pdp_metadata, #{
    id => "/md:PDPDescriptor/@ID",
    valid_until => "/md:PDPDescriptor/@validUntil",
    cache_duration => "/md:PDPDescriptor/@cacheDuration",
    protocols => "/md:PDPDescriptor/@protocolSupportEnumeration",
    error_url => "/md:PDPDescriptor/@errorURL",
    keys => "/md:PDPDescriptor/md:KeyDescriptor",
    organization => "/md:PDPDescriptor/md:Organization",
    contacts => "/md:PDPDescriptor/md:ContactPerson",
    name_id_formats => "/md:PDPDescriptor/md:NameIDFormat",
    authz_query => "/md:PDPDescriptor/md:AuthzService",
    assertion_id_req => "/md:PDPDescriptor/md:AssertionIDRequestService"
    }, ?NS}).
-xml_record({gen_pdp_metadata, saml_pdp_metadata,
    "<md:PDPDescriptor "
        "ID='&id;' validUntil='&valid_until;' cacheDuration='&cache_duration;' "
        "protocolSupportEnumeration='&protocols;' "
        "errorURL='&error_url;'>"
        "&keys;"
        "&organization;"
        "&contacts;"
        "&name_id_formats;"
        "&authz_query;"
        "&assertion_id_req;"
    "</md:PDPDescriptor>", ?NS}).

-xpath_record({match_attr_reqs, saml_attr_reqs, #{
    index => "/md:AttributeConsumingService/@index",
    default => "/md:AttributeConsumingService/@isDefault",
    name => "/md:AttributeConsumingService/md:ServiceName",
    description => "/md:AttributeConsumingService/md:ServiceDescription",
    attrs => "/md:AttributeConsumingService/md:RequestedAttribute"
    }, ?NS}).
-xml_record({gen_attr_reqs, saml_attr_reqs,
    "<md:AttributeConsumingService index='&index;'>"
        "<mxsl:if true='default'>"
            "<mxsl:attribute name='isDefault'>true</mxsl:attribute>"
        "</mxsl:if>"
        "&name;"
        "&description;"
        "&attrs;"
    "</md:AttributeConsumingService>", ?NS}).

-xpath_record({match_sp_metadata, saml_sp_metadata, #{
    id => "/md:SPSSODescriptor/@ID",
    valid_until => "/md:SPSSODescriptor/@validUntil",
    cache_duration => "/md:SPSSODescriptor/@cacheDuration",
    protocols => "/md:SPSSODescriptor/@protocolSupportEnumeration",
    error_url => "/md:SPSSODescriptor/@errorURL",
    keys => "/md:SPSSODescriptor/md:KeyDescriptor",
    organization => "/md:SPSSODescriptor/md:Organization",
    contacts => "/md:SPSSODescriptor/md:ContactPerson",
    name_id_formats => "/md:SPSSODescriptor/md:NameIDFormat",
    authn_reqs_signed => "/md:SPSSODescriptor/@AuthnRequestsSigned",
    want_assertions_signed => "/md:SPSSODescriptor/@WantAssertionsSigned",
    artifact_resolution => "/md:SPSSODescriptor/md:ArtifactResolutionService",
    single_logout => "/md:SPSSODescriptor/md:SingleLogoutService",
    manage_name_id => "/md:SPSSODescriptor/md:ManageNameIDService",
    assertion => "/md:SPSSODescriptor/md:AssertionConsumerService",
    attr_reqs => "/md:SPSSODescriptor/md:AttributeConsumingService",
    ui => "/md:SPSSODescriptor/md:Extensions/mdui:UIInfo"
    }, ?NS}).
-xml_record({gen_sp_metadata, saml_sp_metadata,
    "<md:SPSSODescriptor "
        "ID='&id;' validUntil='&valid_until;' cacheDuration='&cache_duration;' "
        "protocolSupportEnumeration='&protocols;' "
        "errorURL='&error_url;'>"
        "<mxsl:if true='authn_reqs_signed'>"
            "<mxsl:attribute name='AuthnRequestsSigned'>true</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:if true='want_assertions_signed'>"
            "<mxsl:attribute name='WantAssertionsSigned'>true</mxsl:attribute>"
        "</mxsl:if>"
        "&keys;"
        "&organization;"
        "&contacts;"
        "<mxsl:for-each field='name_id_formats' as='x'>"
            "<md:NameIDFormat>&x;</md:NameIDFormat>"
        "</mxsl:for-each>"
        "&assertion;"
        "&single_logout;"
        "&manage_name_id;"
        "&artifact_resolution;"
        "&attr_reqs;"
        "<mxsl:if defined='ui'>"
            "<md:Extensions>"
                "&ui;"
            "</md:Extensions>"
        "</mxsl:if>"
    "</md:SPSSODescriptor>", ?NS}).

-xpath_record({match_idp_metadata, saml_idp_metadata, #{
    id => "/md:IDPSSODescriptor/@ID",
    valid_until => "/md:IDPSSODescriptor/@validUntil",
    cache_duration => "/md:IDPSSODescriptor/@cacheDuration",
    protocols => "/md:IDPSSODescriptor/@protocolSupportEnumeration",
    error_url => "/md:IDPSSODescriptor/@errorURL",
    keys => "/md:IDPSSODescriptor/md:KeyDescriptor",
    organization => "/md:IDPSSODescriptor/md:Organization",
    contacts => "/md:IDPSSODescriptor/md:ContactPerson",
    name_id_formats => "/md:IDPSSODescriptor/md:NameIDFormat",
    want_authn_reqs_signed => "/md:IDPSSODescriptor/@WantAuthnRequestsSigned",
    attribute_profiles => "/md:IDPSSODescriptor/md:AttributeProfile",
    attributes => "/md:IDPSSODescriptor/saml:Attribute",
    artifact_resolution => "/md:IDPSSODescriptor/md:ArtifactResolutionService",
    single_logout => "/md:IDPSSODescriptor/md:SingleLogoutService",
    manage_name_id => "/md:IDPSSODescriptor/md:ManageNameIDService",
    single_sign_on => "/md:IDPSSODescriptor/md:SingleSignOnService",
    name_id_mapping => "/md:IDPSSODescriptor/md:NameIDMappingService",
    ui => "/md:IDPSSODescriptor/md:Extensions/mdui:UIInfo"
    }, ?NS}).
-xml_record({gen_idp_metadata, saml_idp_metadata,
    "<md:IDPSSODescriptor "
        "ID='&id;' validUntil='&valid_until;' cacheDuration='&cache_duration;' "
        "protocolSupportEnumeration='&protocols;' "
        "errorURL='&error_url;'>"
        "<mxsl:if true='want_authn_reqs_signed'>"
            "<mxsl:attribute name='WantAuthnRequestsSigned'>true</mxsl:attribute>"
        "</mxsl:if>"
        "&keys;"
        "&organization;"
        "&contacts;"
        "<mxsl:for-each field='name_id_formats' as='x'>"
            "<md:NameIDFormat>&x;</md:NameIDFormat>"
        "</mxsl:for-each>"
        "&attribute_profiles;"
        "&attributes;"
        "&artifact_resolution;"
        "&single_logout;"
        "&manage_name_id;"
        "&single_sign_on;"
        "&name_id_mapping;"
        "<mxsl:if defined='ui'>"
            "<md:Extensions>"
                "&ui;"
            "</md:Extensions>"
        "</mxsl:if>"
    "</md:IDPSSODescriptor>", ?NS}).

-xpath_record({match_metadata, saml_metadata, #{
    entity_id => "/md:EntityDescriptor/@entityID",
    id => "/md:EntityDescriptor/@ID",
    valid_until => "/md:EntityDescriptor/@validUntil",
    cache_duration => "/md:EntityDescriptor/@cacheDuration",
    organization => "/md:EntityDescriptor/md:Organization",
    contacts => "/md:EntityDescriptor/md:ContactPerson",
    additional_md => "/md:EntityDescriptor/md:AdditionalMetadataLocation",
    idp => "/md:EntityDescriptor/md:IDPSSODescriptor",
    sp => "/md:EntityDescriptor/md:SPSSODescriptor",
    authn => "/md:EntityDescriptor/md:AuthnAuthorityDescriptor",
    attr => "/md:EntityDescriptor/md:AttributeAuthorityDescriptor",
    pdp => "/md:EntityDescriptor/md:PDPDescriptor"
    }, ?NS}).
-xml_record({gen_metadata, saml_metadata,
    "<md:EntityDescriptor entityID='&entity_id;' ID='&id;' "
        "validUntil='&valid_until;' cacheDuration='&cache_duration;'>"
        "&organization;"
        "&contacts;"
        "<mxsl:for-each field='additional_md' as='x'>"
            "<md:AdditionalMetadataLocation>&x;</md:AdditionalMetadataLocation>"
        "</mxsl:for-each>"
        "&idp;"
        "&sp;"
        "&authn;"
        "&attr;"
        "&pdp;"
    "</md:EntityDescriptor>", ?NS}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

samltool_authreq_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltool-authnreq.xml"),
    Rec = match_authn_request(Doc),
    ?assertMatch(#saml_authn_request{
        id = <<"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24">>,
        issue_instant = <<"2014-07-16T23:52:45Z">>,
        destination = <<"http://idp.example.com/SSOService.php">>,
        issuer = #saml_issuer{
            name = <<"http://sp.example.com/demo1/metadata.php">>},
        binding = ?BD_http_post
        }, Rec).

samltool_response_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltool-response.xml"),
    Rec = match_response(Doc),
    ?assertMatch(#saml_response{
        in_response_to = <<"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">>,
        destination = <<"http://sp.example.com/demo1/index.php?acs">>,
        status = #saml_status{code = ?ST_success},
        issuer = #saml_issuer{
            name = <<"http://idp.example.com/metadata.php">>
            },
        assertions = [#saml_assertion{
            subject = #saml_subject{
                name = #saml_name_id{format = ?NF_transient}
                },
            attributes = [
                #saml_attribute{name = <<"uid">>,
                                name_format = ?ANF_basic,
                                values = [<<"test">>]}
            | _]
        }]
        }, Rec).

samltool_logoutreq_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltool-logoutreq.xml"),
    Rec = match_logout_request(Doc),
    ?assertMatch(#saml_logout_request{}, Rec).

samltool_logoutresp_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltool-logoutresp.xml"),
    Rec = match_logout_response(Doc),
    ?assertMatch(#saml_logout_response{}, Rec).

samltest_idp_md_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltest-idp-md.xml"),
    Rec = match_metadata(Doc),
    ?assertMatch(#saml_metadata{entity_id = <<"https://samltest.id/saml/idp">>,
                                sp = undefined, authn = undefined,
                                attr = undefined, pdp = undefined}, Rec),
    #saml_metadata{idp = IDP} = Rec,
    #saml_idp_metadata{protocols = Protos, single_sign_on = SSO} = IDP,
    ProtoList = binary:split(Protos, [<<" ">>, <<"\t">>, <<"\n">>], [global]),
    ?assertMatch(true, lists:member(?PR_saml2, ProtoList)),
    ?assertMatch([_Shib, ?BD_http_post, _PostSimp, ?BD_http_redir, ?BD_soap],
        [Binding || #saml_endpoint{binding = Binding} <- SSO]),
    [Post] = [E || E = #saml_endpoint{binding = ?BD_http_post} <- SSO],
    ?assertMatch(#saml_endpoint{
        location = <<"https://samltest.id/idp/profile/SAML2/POST/SSO">>},
        Post).

samltest_all_md_test() ->
    {ok, Doc} = xmlrat_parse:file("test/samltest-sp-md.xml"),
    Rec = match_metadata(Doc),
    ?assertMatch(#saml_metadata{entity_id = <<"https://samltest.id/saml/sp">>,
                                idp = undefined, authn = undefined,
                                attr = undefined, pdp = undefined}, Rec),
    #saml_metadata{sp = SP} = Rec,
    #saml_sp_metadata{protocols = Protos, assertion = AEP} = SP,
    ProtoList = binary:split(Protos, [<<" ">>, <<"\t">>, <<"\n">>], [global]),
    ?assertMatch(true, lists:member(?PR_saml2, ProtoList)),
    [Post] = [E || E = #saml_endpoint{binding = ?BD_http_post} <- AEP],
    ?assertMatch(#saml_endpoint{index = <<"1">>,
        location = <<"https://samltest.id/Shibboleth.sso/SAML2/POST">>},
        Post).

-endif.

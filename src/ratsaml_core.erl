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

-export([match_assertion/1, gen_assertion/1, match_response/1, gen_response/1]).

-include_lib("ratsaml/include/records.hrl").

-define(NS, #{
    <<"saml">> => ?NS_saml,
    <<"samlp">> => ?NS_samlp
    }).

-xpath_record({match_name_id, saml_name_id, #{
    name_qualifier => "/saml:NameId/@NameQualifier",
    sp_name_qualifier => "/saml:NameId/@SPNameQualifier",
    format => "/saml:NameId/@Format",
    sp_provided_id => "/saml:NameId/@SPProvidedID",
    name => "/saml:NameId/text()"
    }, ?NS}).
-xml_record({gen_name_id, saml_name_id,
    "<saml:NameId "
        "NameQualifier='&name_qualifier;' "
        "SPNameQualifier='&sp_name_qualifier;' "
        "Format='&format;' "
        "SPProvidedID='&sp_provided_id;'>"
        "&name;"
    "</saml:NameId>", ?NS}).

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
    name => "/saml:Subject/saml:NameId",
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

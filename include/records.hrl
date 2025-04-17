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

-define(NS_saml, <<"urn:oasis:names:tc:SAML:2.0:assertion">>).
-define(NS_samlp, <<"urn:oasis:names:tc:SAML:2.0:protocol">>).
-define(NS_dsig, <<"http://www.w3.org/2000/09/xmldsig#">>).
-define(NS_md, <<"urn:oasis:names:tc:SAML:2.0:metadata">>).
-define(NS_mdui, <<"urn:oasis:names:tc:SAML:metadata:ui">>).
-define(NS_xenc, <<"http://www.w3.org/2001/04/xmlenc#">>).
-define(NS_xs, <<"http://www.w3.org/2001/XMLSchema">>).
-define(NS_xsi, <<"http://www.w3.org/2001/XMLSchema-instance">>).

-define(CM_holderOfKey, <<"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">>).
-define(CM_senderVouches, <<"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">>).
-define(CM_bearer, <<"urn:oasis:names:tc:SAML:2.0:cm:bearer">>).

-define(NF_unspec, <<"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">>).
-define(NF_email, <<"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">>).
-define(NF_x509, <<"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">>).
-define(NF_windows, <<"urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName">>).
-define(NF_krb5, <<"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos">>).
-define(NF_entity, <<"urn:oasis:names:tc:SAML:2.0:nameid-format:entity">>).
-define(NF_persistent, <<"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">>).
-define(NF_transient, <<"urn:oasis:names:tc:SAML:2.0:nameid-format:transient">>).

-define(ANF_unspec, <<"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">>).
-define(ANF_uri, <<"urn:oasis:names:tc:SAML:2.0:attrname-format:uri">>).
-define(ANF_basic, <<"urn:oasis:names:tc:SAML:2.0:attrname-format:basic">>).

-define(ST_success, <<"urn:oasis:names:tc:SAML:2.0:status:Success">>).
-define(ST_requester_err, <<"urn:oasis:names:tc:SAML:2.0:status:Requester">>).
-define(ST_responder_err, <<"urn:oasis:names:tc:SAML:2.0:status:Responder">>).
-define(ST_bad_version, <<"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch">>).
-define(ST_authn_fail, <<"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed">>).
-define(ST_bad_attr, <<"urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue">>).
-define(ST_bad_nameid_policy, <<"urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy">>).
-define(ST_no_authn_ctx, <<"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext">>).
-define(ST_no_idp, <<"urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP">>).
-define(ST_no_passive, <<"urn:oasis:names:tc:SAML:2.0:status:NoPassive">>).
-define(ST_bad_idp, <<"urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP">>).
-define(ST_partial_logout, <<"urn:oasis:names:tc:SAML:2.0:status:PartialLogout">>).
-define(ST_denied, <<"urn:oasis:names:tc:SAML:2.0:status:RequestDenied">>).
-define(ST_unsupported, <<"urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported">>).
-define(ST_no_binding, <<"urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding">>).
-define(ST_no_princ, <<"urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal">>).

-define(BD_soap, <<"urn:oasis:names:tc:SAML:2.0:bindings:SOAP">>).
-define(BD_paos, <<"urn:oasis:names:tc:SAML:2.0:bindings:PAOS">>).
-define(BD_http_redir, <<"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">>).
-define(BD_http_post, <<"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">>).
-define(BD_http_artifact, <<"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact">>).
-define(BD_uri, <<"urn:oasis:names:tc:SAML:2.0:bindings:URI">>).

-define(PR_saml2, <<"urn:oasis:names:tc:SAML:2.0:protocol">>).

-type uri() :: binary().
-type unique_id() :: binary().
-type datetime() :: binary().

-record(saml_name_id, {
    name_qualifier :: undefined | uri(),
    sp_name_qualifier :: undefined | uri(),
    format :: undefined | uri(),
    sp_provided_id :: undefined | uri(),
    name :: binary()
    }).

-record(saml_issuer, {
    name_qualifier :: undefined | uri(),
    sp_name_qualifier :: undefined | uri(),
    format :: undefined | uri(),
    sp_provided_id :: undefined | uri(),
    name :: binary()
    }).

-record(saml_subj_confirmation, {
    method :: uri(),
    name :: undefined | #saml_name_id{},
    not_before :: undefined | datetime(),
    not_on_or_after :: undefined | datetime(),
    recipient :: undefined | binary(),
    in_response_to :: undefined | binary(),
    address :: undefined | binary()
    }).

-record(saml_subject, {
    name :: undefined | #saml_name_id{},
    confirmations :: [#saml_subj_confirmation{}]
    }).

-record(saml_conditions, {
    not_before :: undefined | datetime(),
    not_on_or_after :: undefined | datetime(),
    one_time_use = false :: boolean(),
    audiences :: [binary()]
    }).

-record(saml_subj_locality, {
    address :: undefined | binary(),
    dns_name :: undefined | binary()
    }).

-record(saml_authn_context, {
    class_ref :: undefined | uri(),
    authorities :: undefined | [binary()]
    }).

-record(saml_authn_stmt, {
    authn_instant :: datetime(),
    session_index :: undefined | binary(),
    session_not_on_or_after :: undefined | datetime(),
    locality :: undefined | #saml_subj_locality{},
    context :: undefined | #saml_authn_context{}
    }).

-record(saml_attribute, {
    name :: binary(),
    name_format :: undefined | uri(),
    friendly_name :: undefined | binary(),
    values :: [binary()]
    }).

-record(saml_assertion, {
    version = "2.0" :: binary(),
    id :: unique_id(),
    issue_instant :: datetime(),
    issuer :: #saml_issuer{},
    subject :: undefined | #saml_subject{},
    conditions :: undefined | #saml_conditions{},
    authn_stmt :: undefined | #saml_authn_stmt{},
    attributes = [] :: [#saml_attribute{}]
    }).

-record(saml_status, {
    code :: uri(),
    sub_code :: undefined | uri(),
    message :: undefined | binary()
    }).

-record(saml_response, {
    version = "2.0" :: binary(),
    id :: unique_id(),
    issue_instant :: datetime(),
    in_response_to :: undefined | binary(),
    destination :: undefined | uri(),
    consent :: undefined | uri(),
    issuer :: undefined | #saml_issuer{},
    status :: #saml_status{},
    assertions = [] :: [#saml_assertion{}]
    }).

-record(saml_req_authn_context, {
    class_ref :: undefined | uri(),
    comparison :: undefined | binary()
    }).

-record(saml_name_id_policy, {
    format :: undefined | uri(),
    sp_name_qualifier :: undefined | binary(),
    allow_create = false :: boolean()
    }).

-record(saml_authn_request, {
    version = "2.0" :: binary(),
    id :: unique_id(),
    issue_instant :: datetime(),
    destination :: undefined | uri(),
    consent :: undefined | uri(),
    issuer :: undefined | #saml_issuer{},
    subject :: undefined | #saml_subject{},
    name_id_policy :: undefined | #saml_name_id_policy{},
    conditions :: undefined | #saml_conditions{},
    context :: undefined | #saml_req_authn_context{},
    force_authn = false :: boolean(),
    passive = false :: boolean(),
    assertion_svc_index :: undefined | binary(),
    assertion_svc_url :: undefined | uri(),
    attribute_svc_index :: undefined | binary(),
    binding :: undefined | uri(),
    provider_name :: undefined | binary()
    }).

-record(saml_logout_request, {
    version = "2.0" :: binary(),
    id :: unique_id(),
    issue_instant :: datetime(),
    destination :: undefined | uri(),
    consent :: undefined | uri(),
    issuer :: undefined | #saml_issuer{},
    not_on_or_after :: undefined | datetime(),
    reason :: undefined | uri(),
    name_id :: #saml_name_id{},
    session_indexes :: undefined | [binary()]
    }).

-record(saml_logout_response, {
    version = "2.0" :: binary(),
    id :: unique_id(),
    issue_instant :: datetime(),
    in_response_to :: undefined | binary(),
    destination :: undefined | uri(),
    consent :: undefined | uri(),
    issuer :: undefined | #saml_issuer{},
    status :: #saml_status{}
    }).

-record(saml_intl_string, {
    tag :: xmlrat:tag(),
    lang :: undefined | binary(),
    value :: binary()
    }).

-record(saml_organization, {
    name :: [xmlrat:tagged_record(#saml_intl_string{},
        {'md', 'OrganizationName'})],
    display_name :: [xmlrat:tagged_record(#saml_intl_string{},
        {'md', 'OrganizationDisplayName'})],
    url :: [xmlrat:tagged_record(#saml_intl_string{},
        {'md', 'OrganizationURL'})]
    }).

-record(saml_contact, {
    type :: binary(),
    company :: undefined | binary(),
    given_name :: undefined | binary(),
    surname :: undefined | binary(),
    email :: undefined | [binary()],
    phone :: undefined | [binary()]
    }).

-record(saml_key_info, {
    use :: binary(),
    info :: xmlrat:document()
    }).

-record(saml_endpoint, {
    tag :: xmlrat:tag(),
    binding :: uri(),
    location :: uri(),
    response_location :: undefined | uri(),
    index :: undefined | binary(),
    default = false :: boolean()
    }).

-record(saml_ui_logo, {
    lang :: undefined | binary(),
    height :: binary(),
    width :: binary(),
    url :: binary()
    }).

-record(saml_ui_metadata, {
    display_names = [] ::
        [xmlrat:tagged_record(#saml_intl_string{}, {mdui, 'DisplayName'})],
    descriptions = [] ::
        [xmlrat:tagged_record(#saml_intl_string{}, {mdui, 'Description'})],
    keywords = [] ::
        [xmlrat:tagged_record(#saml_intl_string{}, {mdui, 'Keywords'})],
    logos = [] :: [#saml_ui_logo{}],
    info_urls = [] ::
        [xmlrat:tagged_record(#saml_intl_string{}, {mdui, 'InformationURL'})],
    privacy_urls = [] ::
        [xmlrat:tagged_record(#saml_intl_string{}, {mdui, 'PrivacyStatementURL'})]
    }).

-record(saml_idp_metadata, {
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    protocols :: binary(),
    error_url :: undefined | uri(),
    keys = [] :: [#saml_key_info{}],
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],
    ui :: undefined | #saml_ui_metadata{},

    % attributes etc
    name_id_formats = [] :: [uri()],
    want_authn_reqs_signed = false :: boolean(),
    attribute_profiles = [] :: [uri()],
    attributes = [] :: [#saml_attribute{}],

    % endpoints
    artifact_resolution = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'ArtifactResolutionService'})],
    single_logout = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'SingleLogoutService'})],
    manage_name_id = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'ManageNameIDService'})],
    single_sign_on :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'SingleSignOnService'})],
    name_id_mapping = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'NameIDMappingService'})]
    }).

-record(saml_attr_req, {
    required = false :: boolean(),
    name :: binary(),
    name_format :: undefined | uri(),
    friendly_name :: undefined | binary(),
    values :: [binary()]
    }).

-record(saml_attr_reqs, {
    index :: binary(),
    default = false :: boolean(),
    name :: [xmlrat:tagged_record(#saml_intl_string{},
        {md, 'ServiceName'})],
    description = [] :: [xmlrat:tagged_record(#saml_intl_string{},
        {md, 'ServiceDescription'})],
    attrs :: [#saml_attr_req{}]
    }).

-record(saml_sp_metadata, {
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    protocols :: binary(),
    error_url :: undefined | uri(),
    keys = [] :: [#saml_key_info{}],
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],
    ui :: undefined | #saml_ui_metadata{},

    % attributes etc
    name_id_formats = [] :: [uri()],
    authn_reqs_signed = false :: boolean(),
    want_assertions_signed = false :: boolean(),

    % endpoints
    artifact_resolution = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'ArtifactResolutionService'})],
    single_logout = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'SingleLogoutService'})],
    manage_name_id = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'ManageNameIDService'})],
    assertion = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AssertionConsumerService'})],
    attr_reqs = [] :: [#saml_attr_reqs{}]
    }).

-record(saml_authn_metadata, {
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    protocols :: binary(),
    error_url :: undefined | uri(),
    keys = [] :: [#saml_key_info{}],
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],

    % attributes etc
    name_id_formats = [] :: [uri()],

    % endpoints
    authn_query = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AuthnQueryService'})],
    assertion_id_req = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AssertionIDRequestService'})]
    }).

-record(saml_attr_metadata, {
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    protocols :: binary(),
    error_url :: undefined | uri(),
    keys = [] :: [#saml_key_info{}],
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],

    % attributes etc
    name_id_formats = [] :: [uri()],
    profiles = [] :: [uri()],
    attrs = [] :: [#saml_attribute{}],

    % endpoints
    attr_query = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AttributeService'})],
    assertion_id_req = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AssertionIDRequestService'})]
    }).

-record(saml_pdp_metadata, {
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    protocols :: binary(),
    error_url :: undefined | uri(),
    keys = [] :: [#saml_key_info{}],
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],

    % attributes etc
    name_id_formats = [] :: [uri()],

    % endpoints
    authz_query = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AuthzService'})],
    assertion_id_req = [] :: [xmlrat:tagged_record(
        #saml_endpoint{}, {md, 'AssertionIDRequestService'})]
    }).

-record(saml_metadata, {
    entity_id :: uri(),
    id :: undefined | unique_id(),
    valid_until :: undefined | datetime(),
    cache_duration :: undefined | binary(),
    organization :: undefined | #saml_organization{},
    contacts = [] :: [#saml_contact{}],
    additional_md = [] :: [uri()],
    idp :: undefined | #saml_idp_metadata{},
    sp :: undefined | #saml_sp_metadata{},
    authn :: undefined | #saml_authn_metadata{},
    attr :: undefined | #saml_attr_metadata{},
    pdp :: undefined | #saml_pdp_metadata{}
    }).

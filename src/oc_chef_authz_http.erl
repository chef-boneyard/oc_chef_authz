%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Kevin Smith <kevin@opscode.com>
%% @doc oc_chef_authz's interface to the authz server
%%
%% Copyright 2011-2012 Opscode, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%


-module(oc_chef_authz_http).

-define(x_ops_requester_id, "X-Ops-Requesting-Actor-Id").
-define(x_ops_user, {"X-Ops-User-Id", "front-end-service"}).

-type http_body() :: binary() | pid() | [].
-type requestor_id() :: binary().
-type http_method() :: atom().
-type http_path() :: list() | binary().


-export([ping/0,
         request/5]).

%
% Handle raw interaction with authz; set up the headers as expected.
%
-spec request(http_path(), http_method(), any(), http_body(), requestor_id()) -> term() | {error, any()}.
request(Path, Method, Headers, Body, RequestorId) ->
    FullHeaders = [{?x_ops_requester_id, binary_to_list(RequestorId)},
                   ?x_ops_user,
                   {"Accept", "application/json"},
                   {"Content-Type", "application/json"} | Headers
                  ],
    {ok, AuthzHost} = application:get_env(oc_chef_authz, authz_root_url),
    Url = AuthzHost ++ "/" ++ Path,
    case ibrowse:send_req(Url, FullHeaders, Method, Body) of
        {ok, "200", _ResponseHeaders, ResponseBody} = _Response ->
            case ResponseBody of
                "{}" -> ok;
                Raw -> Json = jiffy:decode(Raw),
                       {ok, Json}
            end;
        {ok, "201", _ResponseHeaders, ResponseBody} = _Response ->
            case ResponseBody of
                "{}" -> ok;
                Raw -> Json = jiffy:decode(Raw),
                       {ok, Json}
            end;
        {ok, "403", _H, _B} -> {error, forbidden};
        {ok, "404", _H, _B} -> {error, not_found};
        {ok, "500", _H, _B} -> {error, server_error};
        {ok, ResponseValue, _ResponseHeaders, _ResponseBody} = _Response ->
            {error, ResponseValue};
        {error, Reason} ->
            {error, Reason}
    end.

-spec ping() -> pong | pang.
ping() ->
    try
        {ok, AuthzUrl} = application:get_env(oc_chef_authz, authz_root_url),
        Url = AuthzUrl ++ "/_status",
        Headers = [{"Accept", "application/json"}],
        case ibrowse:send_req(Url, Headers, get) of
            {ok, "200", _H, _B} -> pong;
            _Else -> pang
        end
    catch
        How:Why ->
            error_logger:error_report({oc_chef_authz_http, ping, How, Why}),
            pang
    end.

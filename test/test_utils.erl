%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@opscode.com>
%% @version 0.0.1
%% @end
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

-module(test_utils).

-export([test_setup/0]).

-include_lib("eunit/include/eunit.hrl").

-define(pool_name, pool_name).
-define(pool_opts, [{root_url, "http://www.google.com"}, {max_count, 1}, {init_count, 1}]).

test_setup() ->
    application:set_env(oc_chef_authz, http_pool, [{?pool_name, ?pool_opts}]),
    Server = {context,<<"test-req-id">>,{server,"localhost",5984,[],[]}},
    Superuser = <<"cb4dcaabd91a87675a14ec4f4a00050d">>,
    {Server, Superuser}.


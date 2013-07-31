%% @author Mark Anderson <mark@opscode.com>
%% @version 0.0.1
%% @doc authorization - Interface to the opscode authorization servize
%%
%% This module is an Erlang port of the mixlib-authorization Ruby gem.
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

-module(oc_chef_authz_tests).

-compile([export_all]).

%% -export([raw_request_test_helper/1,
%%          test_setup/0,
%%          test_cleanup/1]).

-include("oc_chef_authz.hrl").

%-define(setup, oc_chef_authz_tests).
-define(setup, test_utils).

-define(SUPERUSER,  <<"platform-superuser">>).
-define(test_org_name, <<"clownco">>).
-define(test_org_id,  <<"0aa7c5c35fbb4f1890c0a673511137af">>).
-define(test_org_admin, <<"clownco-org-admin">>).
-define(test_org_user1, <<"cooky">>).
-define(no_such_id, <<"deadbeefdeadbeefdeadbeefdeadbeef">>).
-define(authz_host, "http://localhost:5959").
-define(chef_host_name, "localhost").
-define(chef_host_port, 5984).

-define(AUTOMECK_FILE(TestName), filename:join(["..", "test", "automeck_config",
                                                atom_to_list(?MODULE) ++ "_" ++ atom_to_list(TestName) ++
                                                    ".config"])).

-include_lib("eunit/include/eunit.hrl").

%% user_lookup_test() ->
%%     test_utils:test_setup(),                    % starts stats_hero
%%     automeck:mocks(?AUTOMECK_FILE(user_lookup)),
%%     Context = chef_db:make_context(<<"testing">>), % req_id must be a binary
%%     ?assert(is_authz_id(oc_chef_authz:username_to_auth_id(Context, ?SUPERUSER))),
%%     meck:unload().

resource_test_() ->
    {foreach,
    fun() ->
            automeck:mocks(?AUTOMECK_FILE(resource)),
            test_utils:test_setup() end,
     fun(_) -> meck:unload() end,
     [fun({_Server, Superuser}) ->
          %% Resource creation
          {"Simple group create",
           fun() ->
               {ok, NewId} = oc_chef_authz:create_resource(Superuser, group),
               true = is_authz_id(NewId)
           end}
      end,
      fun({_Server, Superuser}) ->
              {"Simple group create by non superuser",
               fun() ->
                       {ok, Actor} = oc_chef_authz:create_resource(Superuser, actor),
                       {ok, Group} = oc_chef_authz:create_resource(Actor, group),
                       true = is_authz_id(Group)
               end}
      end,
      fun({_Server, _Superuser}) ->
              {"Simple group create by non-existient user",
               fun() ->
                       {ok, Group} = oc_chef_authz:create_resource(?no_such_id, group),
                       true = is_authz_id(Group)
               end}
      end,
      fun({_Server, Superuser}) ->
              {"group delete",
               fun() ->
                       {ok, NewId} = oc_chef_authz:create_resource(Superuser, group),
                       true = is_authz_id(NewId),
                       ok = oc_chef_authz:delete_resource(Superuser, group, NewId)
               end}
      end,
      fun({_Server, Superuser}) ->
              {"group delete without permission",
               fun() ->
                       {ok, NewId} = oc_chef_authz:create_resource(Superuser, group),
                       true = is_authz_id(NewId),
                       {error, forbidden} = oc_chef_authz:delete_resource(?no_such_id, group, NewId)
               end}
      end,
      fun({_Server, Superuser}) ->
              {"group delete for non-group",
               fun() ->
                       {ok, NewId} = oc_chef_authz:create_resource(Superuser, actor),
                       true = is_authz_id(NewId),
                       {error, server_error} = oc_chef_authz:delete_resource(?no_such_id, group, NewId)
               end}
      end]}.

get_acl_from_resource_test_() ->
    {foreach,
     fun() ->
             automeck:mocks(?AUTOMECK_FILE(get_acl)),
             test_utils:test_setup() end,
     fun(_) -> meck:unload() end,
     [fun({_Server, Superuser}) ->
              {"get the acl for a newly created resource",
               fun() ->
                       {ok, GroupId} = oc_chef_authz:create_resource(Superuser, group),
                       {ok, Acl} = oc_chef_authz:get_acl_for_resource(Superuser, group, GroupId),
                       %%ACE should only contain the superuser
                       lists:foreach(fun(Ace) -> {_Method, #authz_ace{actors=[Superuser],groups=[]}} = Ace end, Acl)
               end}
      end,
      fun({_Server, Superuser}) ->
              {"get the acl for a non existient resource",
               fun() ->
                       %% Should this be remapped?
                       {error, server_error} = oc_chef_authz:get_acl_for_resource(Superuser, group, ?no_such_id)
               end}
      end,
      fun({_Server, Superuser}) ->
              {"get the acl for a resource you don't have rights to",
               fun() ->
                       {ok, GroupId} = oc_chef_authz:create_resource(Superuser, group),
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       ?assertEqual({error, forbidden}, oc_chef_authz:get_acl_for_resource(ActorId, group, GroupId))
               end}
      end]}.

is_authorized_on_resource_test_() ->
    {foreach,
     fun() -> test_utils:test_setup() end,
     fun(_) -> meck:unload() end,
     [fun({_Server, Superuser}) ->
              automeck:mocks(?AUTOMECK_FILE(is_authorized1)),
              {"check if the owner is authorized for grant on a newly created resource",
               fun() ->
                       {ok, ObjectId} = oc_chef_authz:create_resource(Superuser, object),
                       ?assert(oc_chef_authz:is_authorized_on_resource(Superuser, object, ObjectId, actor, Superuser, grant))
               end}
      end,
      fun({_Server, Superuser}) ->
              automeck:mocks(?AUTOMECK_FILE(is_authorized1)),
              {"check that someone else is not authorized for grant on an newly created resource",
               fun() ->
                       {ok, ObjectId} = oc_chef_authz:create_resource(Superuser, object),
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       ?assertNot(oc_chef_authz:is_authorized_on_resource(Superuser, object, ObjectId, actor, ActorId, grant))
               end}
      end,
      fun({_Server, Superuser}) ->
              automeck:mocks(?AUTOMECK_FILE(is_authorized2)),
              {"check that someone else can query permissions on an newly created resource",
               fun() ->
                       {ok, ObjectId} = oc_chef_authz:create_resource(Superuser, object),
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       {ok, GroupId} = oc_chef_authz:create_resource(Superuser, group),
                       ?assert(oc_chef_authz:is_authorized_on_resource(ActorId, object, ObjectId, actor, Superuser, grant)),
                       ?assert(oc_chef_authz:is_authorized_on_resource(ActorId, group, GroupId, actor, Superuser, grant))
               end}
      end,
      fun({_Server, Superuser}) ->
              automeck:mocks(?AUTOMECK_FILE(is_authorized2)),
              {"queries on a nonexistient object fail",
               fun() ->
                       %% would expect not_found
                       ?assertNot(oc_chef_authz:is_authorized_on_resource(Superuser, object, ?no_such_id, actor, Superuser, grant))
               end}
      end,
      fun({_Server, Superuser}) ->
              automeck:mocks(?AUTOMECK_FILE(is_authorized3)),
              {"queries on a object of the wrong type fail",
               fun() ->
                       {ok, ObjectId} = oc_chef_authz:create_resource(Superuser, object),
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       %% would expect server_error
                       ?assertNot(oc_chef_authz:is_authorized_on_resource(Superuser, group, ObjectId, actor, ActorId, grant)),
                       ?assertNot(oc_chef_authz:is_authorized_on_resource(Superuser, object, ObjectId, group, ActorId, grant))
               end}
      end]}.

bulk_actor_is_authorized_test_() ->
    {foreach,
     fun() -> test_utils:test_setup(),
              ibrowse:start(),
              Server = "http://127.0.0.1:9463",
              Superuser = <<"1d774f20735e25fa8a0e97d624b68346">>,
              application:set_env(oc_chef_authz, authz_superuser, Superuser),
              application:set_env(oc_chef_authz, authz_root_url, Server),
              application:set_env(oc_chef_authz, authz_service, [{root_url, Server}, {timeout, 10000000}] ),
              {Server, Superuser}
     end,
     fun(_) -> ibrowse:stop(), meck:unload() end,
     [fun({_Server, Superuser}) ->
%%              automeck:mocks(?AUTOMECK_FILE(bulk_is_authorized1)),
              {"check if the owner is authorized for grant on a newly created resource",
               fun() ->
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       {ok, ObjectId} = oc_chef_authz:create_resource(ActorId, object),
                       ?assert(oc_chef_authz:bulk_actor_is_authorized(<<"">>, ActorId, object, [{ObjectId, ObjectId}], grant))
               end}
      end,
      fun({_Server, Superuser}) ->
%%              automeck:mocks(?AUTOMECK_FILE(bulk_is_authorized2)),
              {"check that someone else is not authorized for grant on an newly created resource",
               fun() ->
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       {ok, ObjectId} = oc_chef_authz:create_resource(Superuser, object),
                       ?assertEqual({false, [ObjectId]}, oc_chef_authz:bulk_actor_is_authorized(<<"">>, ActorId, object, [{ObjectId, ObjectId}], grant))
               end}
      end,
      fun({_Server, Superuser}) ->
%%              automeck:mocks(?AUTOMECK_FILE(bulk_is_authorized3)),
              {"check that we can return mixed results where one is accesible and another isn't",
               fun() ->
                       {ok, ActorId} = oc_chef_authz:create_resource(Superuser, actor),
                       {ok, ObjectId1} = oc_chef_authz:create_resource(Superuser, object),
                       {ok, ObjectId2} = oc_chef_authz:create_resource(Superuser, object),
                       {ok, MyObjectId} = oc_chef_authz:create_resource(ActorId, object),
                       ObjectList = lists:sort( [{O, O} || O <- [ObjectId1, MyObjectId, ObjectId2]] ),
                       ExpectedObjectList = lists:sort([ObjectId1, ObjectId2]),
                       Reply = oc_chef_authz:bulk_actor_is_authorized(<<"">>, ActorId, object, ObjectList, grant),
                       ?assertMatch({false, _}, Reply),
                       {false, ReturnedObjectList} = Reply,
                       ?assertEqual(ExpectedObjectList, lists:sort(ReturnedObjectList))
               end}
      end,
      fun({_Server, Superuser}) ->
%%              automeck:mocks(?AUTOMECK_FILE(bulk_is_authorized3)),
              {"queries on a nonexistient object fail",
               fun() ->
                       %% would expect not_found
                       ?assertEqual({error, {[?no_such_id], "400"}},
                                    oc_chef_authz:bulk_actor_is_authorized(<<"">>, Superuser, object, [{?no_such_id, ?no_such_id}], grant))
               end}
      end]}.



get_container_aid_for_object_test_() ->
    {foreach,
     fun() -> automeck:mocks(?AUTOMECK_FILE(container_aid)),
              test_utils:test_setup() end,
     fun(_) -> meck:unload() end,
     [fun({Context, _Superuser}) ->
              {"Can we get a real container",
               fun() ->
                       ObjectId = oc_chef_authz:get_container_aid_for_object(Context, ?test_org_id, node),
                       ?assert(is_authz_id(ObjectId))
               end}
      end]}.

create_entity_if_authorized_test_() ->
    {foreach,
     fun() -> test_utils:test_setup() end,
     fun(_) -> meck:unload() end,
    [fun({Server, _Superuser}) ->
             automeck:mocks(?AUTOMECK_FILE(create_if_authorized1)),
             {"check if the admin user can create a new object (node)",
              fun() ->
                      AdminAID = <<"cf5d90545fbbac541225fbd9e73e94d9">>,
                      UserAID = <<"cf5d90545fbbac541225fbd9e73e4e42">>,
                      %% so bobo doesn't get created by setup test, probably only by running
                      %% features.
                      %% TODO: also need to decide on behavor for user_record_to_authz_id(not_found)
                      {ok, ObjectId} = oc_chef_authz:create_entity_if_authorized(Server, ?test_org_id, AdminAID, node),
                      ?assert(is_authz_id(ObjectId)),
                      %% the creator should have access
                      [ ?assert(oc_chef_authz:is_authorized_on_resource(AdminAID, object, ObjectId, actor,
                                                                     AdminAID, Method)) || Method <- ?access_methods],
                      %% a regular user should not
                      [ ?assertNot(oc_chef_authz:is_authorized_on_resource(UserAID, object, ObjectId, actor,
                                                                         UserAID, Method)) || Method <- ?access_methods]
              end}
     end,
     fun({Server, _Superuser}) ->
             automeck:mocks(?AUTOMECK_FILE(create_if_authorized2)),
             {"check that someone else is not authorized to create a new object",
              fun() ->
                      UserAID = <<"cf5d90545fbbac541225fbd9e73e4e42">>,
                      ?assertEqual({error, forbidden},
                                   oc_chef_authz:create_entity_if_authorized(Server, ?test_org_id, UserAID, node))
              end}
     end]}.

start_apps() ->
    application:start(ibrowse),
    application:start(oc_chef_authz),
    ok.

stop_apps() ->
    application:stop(oc_chef_authz),
    application:stop(ibrowse),
    ok.

ping_test_() ->
    {foreach,
     fun() ->
             application:set_env(oc_chef_authz, authz_service,
                                 [{root_url, "http://test-authz-service:2323"},
                                  {timeout, 200}]),
             MockMods = [ibrowse, ibrowse_http_client],
             error_logger:tty(false),
             [ meck:new(M) || M <- MockMods ],
             MockMods
     end,
     fun(MockMods) ->
             [ meck:unload(M) || M <- MockMods ],
             error_logger:tty(true),
             ok
     end,
     [
      {"ping pong",
       fun() ->
               FakePid = spawn(fun() -> ok end),
               meck:expect(ibrowse_http_client, start_link,
                           fun("http://test-authz-service:2323") ->
                                   {ok, FakePid}
                           end),
               meck:expect(ibrowse, send_req_direct,
                           fun(Pid, "http://test-authz-service:2323/_ping", _,
                               get, _, _, 200) when Pid =:= FakePid ->
                                   {ok, "200", [], <<"{\"status\":\"ok\"}">>}
                           end),
               ?assertEqual(pong, oc_chef_authz_http:ping())
       end},

      {"ping pang 500",
       fun() ->
               FakePid = spawn(fun() -> ok end),
               meck:expect(ibrowse_http_client, start_link,
                           fun("http://test-authz-service:2323") ->
                                   {ok, FakePid}
                           end),
               meck:expect(ibrowse, send_req_direct,
                           fun(Pid, "http://test-authz-service:2323/_ping", _,
                               get, _, _, 200) when Pid =:= FakePid ->
                                   {ok, "500", [], <<"{\"status\":\"NOT OK\"}">>}
                           end),
               ?assertEqual(pang, oc_chef_authz_http:ping())
       end},

      {"ping pang error",
       fun() ->
               FakePid = spawn(fun() -> ok end),
               meck:expect(ibrowse_http_client, start_link,
                           fun("http://test-authz-service:2323") ->
                                   {ok, FakePid}
                           end),
               meck:expect(ibrowse, send_req_direct,
                           fun(Pid, "http://test-authz-service:2323/_ping", _,
                               get, _, _, 200) when Pid =:= FakePid ->
                                   {error, req_timedout}
                           end),
               ?assertEqual(pang, oc_chef_authz_http:ping())
       end}
      ]}.

join_url_test_() ->
    Root = "root/",
    Tests = [{"foo", "root/foo"},
             {"/foo", "root/foo"}],
    [
     ?_assertEqual(Expect, oc_chef_authz_http:join_url(Root, In))
     || {In, Expect} <- Tests ].

enforce_trailing_slash_test_() ->
    Tests = [{"bare", "bare/"},
             {"with/", "with/"},
             {"onyourown//", "onyourown//"}],
    [ ?_assertEqual(Expect, oc_chef_authz_http:enforce_trailing_slash(In))
      || {In, Expect} <- Tests ].

%% helper for tests
is_authz_id(Id) when is_binary(Id) ->
    case re:run(Id, "[0-9a-f]*", []) of
        {match, _} -> true;
        match -> true;
        nomatch -> false
    end;
is_authz_id(_Id) -> false.

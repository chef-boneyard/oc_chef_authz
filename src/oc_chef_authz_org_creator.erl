%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@getchef.com>
%% Copyright 2014 Chef, Inc. All Rights Reserved.

-module(oc_chef_authz_org_creator).

-export([
         create_org/2,
         create_org/3
       ]).

-ifdef(TEST).
-compile([export_all]).
-endif.

%%
%% This is intended to be a quick reimplementation of the previous group policy
%%
%% Future directions:
%% We will probably want to make the default starting group of a user configurable

-include("oc_chef_authz.hrl").
-include("oc_chef_types.hrl").
-include_lib("chef_objects/include/chef_types.hrl").

%% This is an ACE in human readable form, with chef objects, not
-record(hr_ace, {clients = [],
                 users = [],
                 groups = []}).

%-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
%-endif.

%% A very simple, low level description for an org. This is a short
%% term fix, to get the minimal org creation working. We should
%% come up with a better descriptive system for describing org policy,
%% such as what was done in mixlib-authorization.
%%
-define(CONTAINERS, [clients, containers, cookbooks, data, environments,
                     groups, nodes, roles, sandboxes]).

-define(GROUPS, [admins, 'billing-admins', clients, users]).

-define(ALL_PERMS, [create, read, update, delete, grant]).

-define(DEFAULT_EC_EXPANDED_ORG,
        [{create_containers, ?CONTAINERS},
         {create_groups, ?GROUPS},
         {create_org_global_admins},
         {add_to_groups, user, [creator], [admins, 'billing-admins']},
         {add_to_groups, group, [admins], [global_admins]},

         %% ACLs are expanded, then applied
         {acls,
          [
           %% Billing admins is very restrictive.
           {add_acl, [{group, 'billing-admins'}], [read,update], [{user, creator}]},

           %% Admins
           {add_acl,
            [mk_tl(container, ?CONTAINERS), mk_tl(group, [admins, clients, users]), {organization}],
            ?ALL_PERMS, [{group, admins}]},

           %% users
           {add_acl,
            [mk_tl(container, [cookbooks, data, nodes, roles, environments])],
            [create, read, update, delete], [{group, users}]},

           {add_acl, [{container, clients}], [read, delete], [{group, users}]},
           {add_acl, [mk_tl(container, [groups, containers]), {organization}], [read], [{group, users}]},
           {add_acl, [{container, sandboxes}], [create], [{group, users}]},

           %% clients
           {add_acl, [{container, nodes}], [read, create], [{group, clients}]},
           {add_acl, [{container, data}], [read, create, update, delete], [{group, clients}]},
           {add_acl, mk_tl(container, [cookbooks, environments, roles]), [read] , [{group, clients}]}
          ]
         }
        ]).

%% A little bit of sugar to make a list of Type, Item pairs
mk_tl(Type, List) ->
    [{Type, Item} || Item <- List].

%%
%%

create_org(Org, CreatingUser) ->
    create_org(Org, CreatingUser, ?DEFAULT_EC_EXPANDED_ORG).

create_org(Org, CreatingUser, Policy) ->
    process_policy(Org, CreatingUser, Policy).

%%
%% Execute a policy to create an org
%%

process_policy(#oc_chef_organization{} = Org,
               #chef_user{} = User,
               Policy) ->
    process_policy(Policy, Org, User, init_cache(Org, User)).

process_policy([], _, _, Cache) ->
    Cache;
process_policy([PolicyEntry|Policy], Org, User, Cache) ->
    {Cache1, Steps} = process_policy_step(PolicyEntry, Org, User, Cache),
    process_policy(Steps++Policy, Org, User, Cache1).



%% Returns a tuple of updated cache, and expanded steps to process
%%
process_policy_step({create_containers, List},
                    #oc_chef_organization{id=OrgId}, #chef_user{authz_id=RequestorId}, Cache) ->
    {create_object(OrgId, RequestorId, container, List, Cache), []};
process_policy_step({create_groups, List},
                    #oc_chef_organization{id=OrgId}, #chef_user{authz_id=RequestorId}, Cache) ->
    {create_object(OrgId, RequestorId, group, List, Cache), []};
process_policy_step({set_acl_expanded, Object, Acl},
                    #oc_chef_organization{}, #chef_user{authz_id=_RequestorId}, Cache) ->
    {ResourceType, AuthzId} = find(Object, Cache),
    Acl1 = [{Action, ace_to_authz(Cache, ACE)} || {Action, ACE} <- Acl],
    %% TODO: Error check authz results
    [ oc_chef_authz:set_ace_for_entity(superuser, ResourceType, AuthzId, Method, ACE) ||
        {Method, ACE} <- Acl1],
    {Cache, []};
process_policy_step({add_to_groups, ActorType, Members, Groups},
                    #oc_chef_organization{}, #chef_user{}, Cache) ->
    MemberIds = objectlist_to_authz(Cache, ActorType, Members),
    GroupIds = objectlist_to_authz(Cache, group, Groups),
    %% TODO capture error return
    [oc_chef_authz:add_to_group(GroupId, Type, MemberId, superuser) ||
        {_, GroupId} <- GroupIds,
        {Type,MemberId} <- MemberIds],
    {Cache, []};
process_policy_step({create_org_global_admins},
                    #oc_chef_organization{name=OrgName},
                    #chef_user{authz_id=RequestorId}, Cache) ->
    GlobalGroupName = oc_chef_authz_db:make_global_admin_group_name(OrgName),
    %% TODO: Fix this to be the global groups org id.
    GlobalOrgId = ?GLOBAL_PLACEHOLDER_ORG_ID,
    Cache1 = case create_helper(GlobalOrgId, RequestorId, group, GlobalGroupName) of
                 AuthzId when is_binary(AuthzId) ->
                     add_cache(Cache, {group, global_admins}, group, AuthzId);
                 Error ->
                     throw(Error)
             end,
    {Cache1, []};
process_policy_step({acls, Steps}, _Org, _User, Cache) ->
    {Cache, process_acls(Steps)}.

%%
%% Sequence of operations to create an object in authz and in chef sql.
%%
create_object(_, _, _, [], Cache) ->
    Cache;
create_object(OrgId, RequestorId, Type, [Name|Remaining], Cache) ->
    case create_helper(OrgId, RequestorId, Type, Name) of
        AuthzId when is_binary(AuthzId) ->
            NewCache = add_cache(Cache,{Type, Name}, AuthzId),
            create_object(OrgId, RequestorId, Type, Remaining, NewCache);
        Error ->
            %% Do we clean up created authz stuff here, or save it for
            %% general org deletion routine later?
            lager:error("Could not create object ~p during creation of org ~s", 
                        [{Type, Name}, OrgId]),
            throw(Error)
    end.

create_helper(OrgId, RequestorId, Type, Name) when is_atom(Name) ->
    BinaryName = atom_to_binary(Name, utf8),
    create_helper(OrgId, RequestorId, Type, BinaryName);
create_helper(OrgId, RequestorId, Type, Name) ->
    case oc_chef_authz:create_resource(RequestorId, Type) of
        {ok, AuthzId} ->
            create_chef_side(OrgId, RequestorId, Type, Name, AuthzId);
        {error, _} = Error ->
            Error
    end.

create_chef_side(OrgId, RequestorId,  container, Name, AuthzId) ->
    Data = ej:set({<<"containername">>}, {[]}, Name),
    Object =chef_object:new_record(oc_chef_container, OrgId, AuthzId, Data),
    create_insert(Object, AuthzId, RequestorId);
create_chef_side(OrgId, RequestorId, group, Name, AuthzId) ->
    Data = ej:set({<<"groupname">>}, {[]}, Name),
    Object = chef_object:new_record(oc_chef_group, OrgId, AuthzId, Data),
    create_insert(Object, AuthzId, RequestorId).

create_insert(Object, AuthzId, RequestorId) ->
    ObjectRec = chef_object:set_created(Object, RequestorId),
    case chef_sql:create_object(chef_object:create_query(ObjectRec), chef_object:flatten(ObjectRec)) of
        {ok, 1} ->
            AuthzId;
        Error ->
            {chef_sql, {Error, ObjectRec}}
    end.

%%
%% Helper for creating acls. It's very tedious to write them all out longhand.
%% {add, Objects, Actions, Members}
%%
%% We keep the human readable names throughout this expansion.  We could probably be more
%% efficient to translate to authz ids earlier, at the cost of a lot of readability
process_acls(AclDesc) ->
    AclMap = lists:foldl(fun update_acl_step/2, dict:new(), lists:flatten(AclDesc)),
    [{set_acl_expanded, Object, Acl} || {Object, Acl} <- dict:to_list(AclMap)].

%% {add, Objects, Actions, Members}
%% Objects: {type, Name} pairs
%% Methods: CRUDG
%% Members: {user|group, name}
%% Adds cross product to existing world
update_acl_step({add_acl, Objects, Actions, Members}, Acls) ->
    %% split out actors and groups separately
    {Clients, Users, Groups} = lists:foldl(
                                 fun(M, {C, U, G}) ->
                                         case M of
                                             {user, N} ->
                                                 {C, [N|U],G};
                                             {client, N} ->
                                                 {[N|C], U, G};
                                             {group, N} ->
                                                 {C, U, [N|G]}
                                         end
                                 end, {[], [], []}, lists:flatten(Members)),
    AceToAdd = #hr_ace{clients=Clients, users=Users, groups=Groups},
    ObjUpdate = fun(Acl) ->
                           update_acl(Acl, Actions, AceToAdd)
                   end,
    lists:foldl(fun(Object, Acc) ->
                        update_acl_for_object(ObjUpdate, Acc, Object)
                end,
                Acls, lists:flatten(Objects)).

update_acl(Acl, Actions, AceToAdd) ->
    UpdateFun = fun(Ace) ->
                        add_to_ace(Ace, AceToAdd)
                end,
    lists:foldl(fun(Action, AAcl) ->
                        update_ace_by_action(UpdateFun, AAcl, Action)
                end,
                Acl, lists:flatten(Actions)).

% lookup acl for object, create new if missing, apply function, and set it
update_acl_for_object(UpdateFun, Acls, Object) ->
    Acl0 = case dict:find(Object, Acls) of
               {ok, V} -> V;
               error -> []
           end,
    Acl1 = UpdateFun(Acl0),
    dict:store(Object, Acl1, Acls).

% lookup ace for action, create new if missing, apply function, and set it
update_ace_by_action(UpdateFun, Acl, Action) ->
    Ace0 = case lists:keyfind(Action, 1, Acl) of
                         false -> #hr_ace{};
                         {_, A} -> A
                     end,
    Ace1 = UpdateFun(Ace0),
    lists:keystore(Action, 1, Acl, {Action, Ace1}).

merge(Old, New) ->
    lists:umerge(Old, lists:sort(New)).

add_to_ace(#hr_ace{clients=OClients, users=OUsers, groups=OGroups},
           #hr_ace{clients=Clients, users=Users, groups=Groups}) ->
    NClients = merge(OClients, Clients),
    NUsers = merge(OUsers, Users),
    NGroups = merge(OGroups, Groups),
    #hr_ace{clients=NClients, users=NUsers, groups=NGroups}.

%%
%% Simple cache for managing object-> authzid mapping.
%%
init_cache(#oc_chef_organization{authz_id=OrgAuthzId},
           #chef_user{authz_id=CreatorAuthzId}) ->
    %% Notes: we assume the creator is a superuser;
    Elements = [ { {user, creator}, CreatorAuthzId },
                 { {organization}, OrgAuthzId } ],
    InsertFun = fun({Item,AuthzId}, Acc) ->
                        add_cache(Acc, Item, AuthzId)
                end,
    lists:foldl(InsertFun, dict:new(), Elements).

add_cache(C, Object, Type, AuthzId) ->
    set(Object, {Type, AuthzId}, C).

add_cache(C, {Type, Object}, AuthzId) ->
    Resource = oc_chef_authz:object_type_to_resource(Type),
    set({Type, Object}, {Resource, AuthzId}, C);
add_cache(C, {Type}, AuthzId) ->
    Resource = oc_chef_authz:object_type_to_resource(Type),
    set({Type}, {Resource, AuthzId}, C).

objectlist_to_authz(C, ObjectList) ->
    [find(O,C) || O <- lists:flatten(ObjectList)].

objectlist_to_authz(C, Type, BareObjectList) ->
    [find({Type,O},C) || O <- lists:flatten(BareObjectList)].

ace_to_authz(C, #hr_ace{clients=Clients, users=Users, groups=Groups}) ->
    {_, ClientIds} = lists:unzip(objectlist_to_authz(C, client, Clients)),
    {_, UserIds} = lists:unzip(objectlist_to_authz(C, user, Users)),
    {_, GroupIds} = lists:unzip(objectlist_to_authz(C, group, Groups)),
    ActorIds = lists:flatten([ClientIds, UserIds]),
    #authz_ace{actors=ActorIds,groups=GroupIds}.

set(Key, Value, C) ->
    dict:store(Key,Value, C).

find(Key, C) ->
    case dict:find(Key,C) of
        {ok, Value} -> Value;
        error ->
            lager:error("Error processing org creation policy, no definition found for ~p", [Key]),
            throw( {error, bad_org_creation_policy})
    end.

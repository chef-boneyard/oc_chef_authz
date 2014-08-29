%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Mark Anderson <mark@getchef.com>
%% Copyright 2014 Opscode, Inc. All Rights Reserved.

-module(oc_chef_authz_org_creator).

-export([
         create_org/2,
         create_org/3
       ]).
%%
%% This is intended to be a quick reimplementation of the previous group policy
%%
%% Future directions:
%% We will probably want to make the default starting group of a user configurable
%% global_admins might be better replaced with
%%-define(DEFAULT_EC_POLICY,
%%        [{containers, [clients, containers, cookbooks, data, environments,
%%                       groups, nodes, roles, sandboxes]},
%%         {groups, [admins, 'billing-admins', clients, users]},
%%         {global_admins_group},
%%         {add_group_members, [admins,users,clients], [superuser], []},
%%         {add_group_rights, admins, all, [{containers, all}, {groups, [admins, clients, users]}]}
%%
%%
%%         {add_group_rights, admins, all, [{containers, all}, {groups, [admins, clients, users]}]}
%%
%%         {add_group_rights, users, [create, read, update, delete],
%%          [{containers, all}, {groups, [admins, clients, users]}]}
%%        ]).

-include("oc_chef_authz.hrl").
-include("oc_chef_types.hrl").
-include_lib("chef_objects/include/chef_types.hrl").

%% A very simple, low level description for an org. This is a short
%% term fix, to get the minimal org creation working. We should
%% come up with a better descriptive system for describing org policy,
%% such as what was done in mixlib-authorization.
%%
-define(DEFAULT_EC_EXPANDED_ORG,
        [{create_containers, [clients, containers, cookbooks, data, environments,
                              groups, nodes, roles, sandboxes]},
         {create_groups, [admins, 'billing-admins', clients, users]},
         {create_org_global_admins},
         {add_to_groups, user, [creator], [admins, 'billing-admins']},
         {add_to_groups, group, [admins], [global_admins]},
         {set_acl, [{group, 'billing-admins'}],
          [{create, [creator], []},
           {read, [creator], ['billing-admins']},
           {update, [creator], ['billing-admins']},
           {delete, [creator], []},
           {grant, [creator], []}]},
         {set_acl, [{group, admins}, {group, users}, {group, clients}, {organization}],
          [{create, [creator], [admins]},
           {read, [creator], [admins]},
           {update, [creator], [admins]},
           {delete, [creator], [admins]},
           {grant, [creator], [admins]}]},
         {set_acl, [{container, clients}], [{read, [], []}]}
        ]).

create_org(Org, CreatingUser) ->
    create_org(Org, CreatingUser, ?DEFAULT_EC_EXPANDED_ORG).

create_org(Org, CreatingUser, Policy) ->
    process_policy(Org, CreatingUser, Policy).


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

ace_to_authz(C, {Method, Actors, Groups}) ->
    {_, ActorIds} = lists:unzip(objectlist_to_authz(C, user, Actors)),
    {_, GroupIds} = lists:unzip(objectlist_to_authz(C, group, Groups)),
    {Method, #authz_ace{actors=ActorIds,groups=GroupIds}}.

set(Key, Value, C) ->
    dict:store(Key,Value, C).

find(Key, C) ->
    case dict:find(Key,C) of
        {ok, Value} -> Value;
        error ->
            lager:error("Error processing org creation policy, no definition found for ~p", [Key]),
            throw( {error, bad_org_creation_policy})
    end.

%%
%% Execute a policy to create an org
%%

process_policy(#oc_chef_organization{} = Org,
               #chef_user{} = User,
               Policy) ->
    process_policy(Policy, Org, User, init_cache(Org, User)).

process_policy([], _, _, _) ->
    Cache;
process_policy([PolicyEntry|Policy], Org, User, Cache) ->
    Cache1 = process_policy_step(PolicyEntry, Org, User, Cache),
    process_policy(Policy, Org, User, Cache1).

process_policy_step({create_containers, List},
                    #oc_chef_organization{id=OrgId}, #chef_user{authz_id=RequestorId}, Cache) ->
    create_object(OrgId, RequestorId, container, List, Cache);
process_policy_step({create_groups, List},
                    #oc_chef_organization{id=OrgId}, #chef_user{authz_id=RequestorId}, Cache) ->
    create_object(OrgId, RequestorId, group, List, Cache);
process_policy_step({set_acl, ObjectList, ACL},
                    #oc_chef_organization{}, #chef_user{authz_id=RequestorId}, Cache) ->
    AObjectList = objectlist_to_authz(Cache, ObjectList),
    AACL = [ace_to_authz(Cache, ACE) || ACE <- ACL],
    %% Note that this list comprehension generates the cross product of objectlist and acl
    %% TODO: Error check authz results
    [oc_chef_authz:set_ace_for_entity(RequestorId, ResourceType, ResourceId, Method, ACE) ||
        {ResourceType, ResourceId} <- AObjectList,
        {Method, ACE} <- AACL],
    Cache;
process_policy_step({add_to_groups, ActorType, Members, Groups},
                    #oc_chef_organization{}, #chef_user{}, Cache) ->
    MemberIds = objectlist_to_authz(Cache, ActorType, Members),
    GroupIds = objectlist_to_authz(Cache, group, Groups),
    %% TODO capture error return
    [oc_chef_authz:add_to_group(GroupId, Type, MemberId, superuser) ||
        {_, GroupId} <- GroupIds,
        {Type,MemberId} <- MemberIds],
    Cache;
process_policy_step({create_org_global_admins},
                    #oc_chef_organization{name=OrgName},
                    #chef_user{authz_id=RequestorId}, Cache) ->
    GlobalGroupName = oc_chef_authz_db:make_global_admin_group_name(OrgName),
    %% TODO: Fix this to be the global groups org id.
    GlobalOrgId = ?GLOBAL_PLACEHOLDER_ORG_ID,
    case create_helper(GlobalOrgId, RequestorId, group, GlobalGroupName) of
        AuthzId when is_binary(AuthzId) ->
            add_cache(Cache, {group, global_admins}, group, AuthzId);
        Error ->
             throw(Error)
    end.

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

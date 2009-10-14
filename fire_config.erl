%%%-------------------------------------------------------------------
%%% File    : fire_config.erl
%%% Author  : Matthias <matthias@corelatus.com>
%%% Description : Manages the configuration for the whole firewall
%%%
%%% Created :  3 Mar 2003 by Matthias <matthias@corelatus.com>
%%%
%%%
%%% Copyright (c) 2003, Matthias Lang
%%% All rights reserved.
%%% 
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%     * Redistributions of source code must retain the above copyright
%%%       notice, this list of conditions and the following disclaimer.
%%%     * Redistributions in binary form must reproduce the above copyright
%%%       notice, this list of conditions and the following disclaimer in the
%%%       documentation and/or other materials provided with the distribution.
%%%     * Neither the name of Matthias Lang nor the
%%%       names of its contributors may be used to endorse or promote products
%%%       derived from this software without specific prior written permission.
%%% 
%%% THIS SOFTWARE IS PROVIDED BY Matthias Lang ''AS IS'' AND ANY
%%% EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
%%% PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Matthias Lang BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
%%% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
%%% OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
%%% BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
%%% USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
%%% DAMAGE.
%%%
%%%-------------------------------------------------------------------
-module(fire_config).
-behaviour(gen_server).
%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% External exports
-export([start_link/0, lookup/1, timed_access_whitelist/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {adsl_bandwidth,
		dyndns_host, dyndns_auth, 
		int_net,    % {Net, Mask}, two 32 bit numbers
		ext_if = "eth1",
		log_dir,
		aliases,          % dict string() -> {host, user, pwd}
		timed_access_whitelist = [],   % [IP_quad]
		services = []     % [{Type, ...}]
	       }).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

lookup(What) ->
    gen_server:call(?MODULE, What).

timed_access_whitelist(List) ->
    gen_server:call(?MODULE, {timed_access_whitelist, List}).

%%--------------------------------------------------------------------
init([]) ->
    {ok, from_file()}.

%%--------------------------------------------------------------------
handle_call(adsl_user, _From, State) ->
    {value, {autologin, User, Pwd}} = 
	lists:keysearch(autologin, 1, State#state.services),
    Reply = {User, Pwd},
    {reply, Reply, State};

handle_call(aliases, _From, State) ->
    Reply = State#state.aliases,
    {reply, Reply, State};

handle_call(adsl_bandwidth, _From, State) ->
    Reply = State#state.adsl_bandwidth,
    {reply, Reply, State};

handle_call(dyndns_auth, _From, State) ->
    Reply = {State#state.dyndns_host, State#state.dyndns_auth},
    {reply, Reply, State};

handle_call(external_if, _From, State) ->
    Reply = State#state.ext_if,
    {reply, Reply, State};

handle_call(int_net, _From, State) ->
    Reply = State#state.int_net,
    {reply, Reply, State};

handle_call(log_dir, _From, State) ->
    Reply = State#state.log_dir,
    {reply, Reply, State};

handle_call(services, _From, State) ->
    Reply = State#state.services,
    {reply, Reply, State};

handle_call(timed_access_whitelist, _From, State) ->
    Reply = State#state.timed_access_whitelist,
    {reply, Reply, State};

handle_call({timed_access_whitelist, List}, _From, State) ->
    {reply, ok, State#state{timed_access_whitelist=List}};

handle_call(_X, _From, State) ->
    {reply, undefined, State}.

%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%% Returns: {ok, NewState}
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

%% Config-file reader. Returns a state record.
from_file() -> 
    from_file([".firerc", "firerc"]).

from_file([H|T]) ->
    case file:open(H, [read]) of
      {ok, In} -> lines(In, #state{aliases = dict:new()});
	_ -> from_file(T)
    end.

%% Handle one line of the config file at a time
lines(In, State) ->
    Services = State#state.services,
    case io:get_line(In, "") of
	eof ->
	    State;

	[Head|_]  when Head == $#; Head == $\n ->
	    ignore,
	    lines(In, State);

	"bandwidth " ++ Tail ->
	    [BW] = string:tokens(Tail, "\n "),
	    lines(In, State#state{adsl_bandwidth = list_to_integer(BW)});

	"dns " ++ Tail ->
	    [DNS] = string:tokens(Tail, "\n "),
	    {ok, Quad} = inet:getaddr(DNS, inet),
	    Service = {dns_proxy, Quad},
	    lines(In, State#state{services = [Service|Services]});

	"dyndns " ++ Tail ->
	    [Host, Auth] = string:tokens(Tail, "\n "),
	    lines(In, State#state{dyndns_host = Host, dyndns_auth = Auth});

	"external_if " ++ Tail ->
	    [If] = string:tokens(Tail, "\n "),
	    lines(In, State#state{ext_if = If});

	"internal_if " ++ Tail ->
	    [If] = string:tokens(Tail, "\n "),
	    {ok, [{netmask, {A,B,C,D}}, {addr, {E,F,G,H}}]} = 
		inet:ifget(If, [netmask, addr]),
	    <<Mask:32, Net:32>> = <<A,B,C,D,  E,F,G,H>>,
	    lines(In, State#state{int_net = {Net band Mask, Mask}});

	"log_dir " ++ Tail ->
	    [Dir] = string:tokens(Tail, " \t\n"),
	    lines(In, State#state{log_dir = Dir});

	"registrar " ++ Tail ->
	    [A_port|Users] = string:tokens(Tail, " \t\n"),
	    Port = list_to_integer(A_port),
	    Service = {registrar, Port, Users},
	    lines(In, State#state{services = [Service|Services]});

	List ->
	    [ALPort, Host, ARPort|Allowed] = string:tokens(List, " \t\n"),
	    LPort = list_to_integer(ALPort),
	    RPort = list_to_integer(ARPort),
	    Service = {plain_forward, LPort, Host, RPort, Allowed},
	    lines(In, State#state{services = [Service|Services]})
    end.


%%%-------------------------------------------------------------------
%%% File    : registrar.erl
%%% Author  : Matthias <matthias@corelatus.com>
%%% Description : IP address registrar
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
%%% Created : 12 Jul 2004 by Matthias <matthias@corelatus.com>
%%%-------------------------------------------------------------------
-module(registrar).

-behaviour(gen_server).
%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% External exports
-export([start_link/2, is_registered/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {users = [], lsock, whitelist = []}).

%% How many entries to have in the whitelist
-define(WHITELIST_SIZE, 5).

%%====================================================================
%% External functions
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link/0
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link(Port, Users) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Users], []).

is_registered(IP) ->
    gen_server:call(?MODULE, {is_ip_allowed,IP}).

%%====================================================================
%% Server functions
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init/1
%% Description: Initiates the server
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%%--------------------------------------------------------------------
init([Port, Users]) ->
    {ok, L} = gen_tcp:listen(Port, [{active, false}, 
				    {packet, line}, {reuseaddr, true}]),
    Self = self(),
    spawn_link(fun() -> acceptor(L, Self) end),
    {ok, #state{lsock = L, users = Users}}.

%%--------------------------------------------------------------------
%% Function: handle_call/3
%% Description: Handling call messages
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------
handle_call({is_ip_allowed, IP}, _From, State) ->
    Reply = lists:member(IP, State#state.whitelist),
    %% If it's a successful lookup, move the lookup to the front of the list
    Newlist = case Reply of
		  true -> [IP|lists:delete(IP, State#state.whitelist)];
		  _ -> State#state.whitelist
	      end,
    {reply, Reply, State#state{whitelist = Newlist}};

handle_call({password_ok, IP, Base64}, _From, State) ->
    Stripped = [X || X <- Base64, X =/= $\r, X =/= $\n],
    Filtered = [Addr || Addr <- State#state.whitelist, Addr =/= IP],
    case lists:member(Stripped, State#state.users) of
	true ->
	    Whitelist = lists:sublist([IP | Filtered], ?WHITELIST_SIZE),
	    reflect:log("registrar: whitelist is now ~p\n", [Whitelist]),
	    {reply, true, State#state{whitelist = Whitelist}};
	_ ->
	    io:fwrite("password: ~p\n", [Stripped]),
	    reflect:log("registrar: bad password from ~p\n", [IP]),
	    {reply, false, State}
    end.

%%--------------------------------------------------------------------
%% Function: handle_cast/2
%% Description: Handling cast messages
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info/2
%% Description: Handling all non call/cast messages
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {stop, unexpected_info, State}.

%%--------------------------------------------------------------------
%% Function: terminate/2
%% Description: Shutdown the server
%% Returns: any (ignored by gen_server)
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change/3
%% Purpose: Convert process state when code is changed
%% Returns: {ok, NewState}
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Accept a socket. We then give it 10s to handle the HTTP request.
%% If there's no password there, send a 401.
%% If there is a username/password there, tell the registrar about it.
acceptor(L, Pid) ->
    case gen_tcp:accept(L) of
	{ok, S} ->
	    spawn(fun() -> handle_http_request(S, Pid) end),
	    spawn(fun() -> timer:sleep(10000), gen_tcp:close(S) end);
	_ ->
	    never_mind
    end,
    timer:sleep(1000), % throttle
    acceptor(L, Pid).

handle_http_request(S, Pid) ->
    case gen_tcp:recv(S, 0) of
	{ok, "Authorization: Basic " ++ Pwd} ->
	    {ok, {Client_ip, _Client_port}} = inet:peername(S),
	    case gen_server:call(Pid, {password_ok, Client_ip, Pwd}) of
		true ->
		    response_ok(S, io_lib:fwrite("~p is go\n", [Client_ip]));
		_ ->
		    response_401(S, "no way jose\n")
	    end;

	{ok, "\r\n"} ->
	    response_401(S, "and don't come back\n");

	{ok, _X} ->
	    handle_http_request(S, Pid);

	_ ->
	    never_mind
    end.
    
response_ok(S, Body) ->
    gen_tcp:send(S, "HTTP/1.0 200 OK\r\n"),
    gen_tcp:send(S, "Content-type: text/plain\r\n\r\n"),
    gen_tcp:send(S, Body),
    gen_tcp:close(S).

response_401(S, Body) ->
    gen_tcp:send(S, "HTTP/1.0 401 Authorization required\r\n"),
    gen_tcp:send(S, "WWW-Authenticate: Basic realm=\"intranet\"\r\n"),
    gen_tcp:send(S, "Content-type: text/plain\r\n\r\n"),
    gen_tcp:send(S, Body),
    gen_tcp:close(S).

    
    

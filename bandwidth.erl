%%%-------------------------------------------------------------------
%%% File    : bandwidth.erl
%%% Author  : Matthias <matthias@corelatus.com>
%%% Description : Bandwidth manager. Part of the erlang plug proxy, see 
%%%               reflect.erl
%%%
%%% Created :  1 Mar 2003 by Matthias <matthias@corelatus.com>
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


%%%-------------------------------------------------------------------
-module(bandwidth).

-behaviour(gen_server).
%%--------------------------------------------------------------------
%% Include files
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% External exports
-export([start_link/0, new_delay/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {nominal = 56   % nominal bandwidth of link in kByte/s
	       }).

%%====================================================================
%% External functions
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link/0
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Returns how many milliseconds to sleep between calls to recv()
%%
%% Diff: time difference since last call (in milliseconds)
%% Bytes: the bandwidth consumed (in bytes)
new_delay(Old, Diff, Bytes) ->
    gen_server:call(?MODULE, {new_delay, Old, Diff, Bytes}).

%%====================================================================
%% Server functions
%%====================================================================

%%--------------------------------------------------------------------
init([]) ->
    {ok, #state{nominal = fire_config:lookup(adsl_bandwidth)}}.

%%--------------------------------------------------------------------
handle_call({nominal, N}, _From, State) when integer(N) ->
    {reply, ok, State#state{nominal = N}};

handle_call({new_delay, Old, Diff, Bytes}, _From, State) ->
    Bandwidth = Bytes div Diff,   % answer is in kByte/s
    #state{nominal = Nominal} = State,
    New_delay = compute_delay(Old, Bandwidth, Nominal),
    io:fwrite("compute(~p, ~p, ~p) -> ~p\n", 
	      [Old, Bandwidth, Nominal, New_delay]),
    {reply, New_delay, State}.

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
    {noreply, State}.

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

compute_delay(0, Bandwidth, Nominal) ->
    case 10 * Bandwidth < Nominal of
	true -> 0;
	_ -> 300 div Nominal   %% Assume 1kByte packets
    end;

compute_delay(Old, Bandwidth, Nominal) ->
    if 
	(2 * Bandwidth < Nominal) -> (Old * 6) div 10;
	(5 * Bandwidth < 4 * Nominal) -> (Old * 8) div 10;
	(10 * Bandwidth < 9 * Nominal) -> (Old * 9) div 10;
	(20 * Bandwidth < 19 * Nominal) -> (Old * 10) div 9;
	true -> Old * 2
    end.
    
	    
    
	    
    
    

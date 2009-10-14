%% The DNS provided by my ISP isn't very reliable. 
%% One way to fix that would be to run a DNS server on my firewall.
%% Another way is to have a fallback DNS in the erlang code.
%% That's what this module does.
%%
%% It's an ets table:
%%    hostname -> {quad, last_updated, last_used}
%%
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


-module(dns_cache).
-export([start_link/0, lookup/1]).

-export([flusher/0]).

%%======================================================================
%% Interface

start_link() ->
    _Table = ets:new(dns_cache, [set, public, named_table]),
    spawn_link(fun flusher/0),
    ok.

%% return: error | {ok, Quad}
lookup(Host) ->
    lookup(Host,1).

lookup(Host,Attempt) when Attempt > 5 ->
    reflect:log("lookup of '~p' failed, trying ETS.\n", [Host]),
    ets_lookup(Host);

lookup(Host,Attempt) ->
    Ref = make_ref(),
    Parent = self(),
    F = fun() ->
		case inet:getaddr(Host, inet) of
		    {ok, Quad} -> 
			Parent ! {Ref, Quad};

		    {error, Reason} -> 
			io:fwrite("DNS lookup failed: ~p\n", [Reason]),
			Parent ! {Ref, error}
		end
	end,
    _Child = spawn(F),
    receive
	{Ref, error} -> 
	    io:fwrite("DNS lookup for ~p failed\n", [Host]),
	    error;
	{Ref, Quad} -> 
	    update_cache(Host, Quad),
	    {ok, Quad}
    after 1000
	  -> %% Retry
	    reflect:log("lookup timeout for '~p'\n", [Host]),
	    lookup(Host,Attempt+1)
    end.

%%======================================================================
%% Internals

%% Store a lookup in the cache. If it's already there, freshen the timestamps.
%% Concurrent access is not a problem, it doesn't matter if another process
%% overwrites the data we've just written.
update_cache(Host, Quad) ->
    Entry = case ets:lookup(dns_cache, Host) of
		[] -> {Host, Quad, now(), now()};
		[{Host, Quad, _Updated, _Used}] -> {Host, Quad, now(), now()};
		[{Host, _, _Updated, _Used}] -> {Host, Quad, now(), now()}
	    end,
    ets:insert(dns_cache, Entry).

%% The regular lookup failed, see if we have it in ETS
%% Return: error | Quad
ets_lookup(Host) ->
    case ets:lookup(dns_cache, Host) of
	[] -> 
	    reflect:log("ETS didn't have the host: ~p", [Host]),
	    not_cached;
	[{Host, Quad, Updated, _Used}] ->
	    ets:insert(dns_cache, {Host, Quad, Updated, now()}),
	    {ok, Quad}
    end.

%% Process to throw out stale entries. Again, concurrency isn't a problem
%% here. 
flusher() ->
    {NM, NS, _} = now(),
    F = fun({Host, _Quad, Updated, Used}, Hosts) ->
		{PM, PS, _} = Updated,
		{SM, SS, _} = Used,
		Update_staleness = ((NM - PM) * 1000000 + (NS - PS)),
		Use_staleness    = ((NM - SM) * 1000000 + (NS - SS)),
		if
		    Update_staleness > (3600 * 24) -> [Host|Hosts];
		    Use_staleness > 3600 -> [Host|Hosts];
		    true -> Hosts
		end
	end,
    Stale = ets:foldl(F, [], dns_cache),
    lists:foreach(fun(Host) -> ets:delete(dns_cache, Host) end, Stale),
    case Stale of
	[] -> shut_up;
	_ ->
	    reflect:log("flushing ~p entries from the DNS cache\n", 
			[length(Stale)])
    end,
    timer:sleep(60 * 1000),	%% throttle
    dns_cache:flusher().

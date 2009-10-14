%% Generalised TCP-proxy firewall. Does some things similarly to 'plug-gw'.
%%
%% The config is read from the file ".firerc" or "firerc"
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
%%
-module(reflect).
-export([go/0, supervise/0, loop/2, loop_body/4, log/1, log/2,
	 connection_allowed/2]).

%% Exports to allow code loading
-export([teleport/3]).

go() ->
    process_flag(trap_exit, true),
    fire_config:start_link(),
    file:make_dir(fire_config:lookup(log_dir)),  % usually returns eexist
    {ok, _Log} = disk_log:open([{name, proxy}, 
			       {file, fire_config:lookup(log_dir) ++ "proxy"}, 
			       {repair, true}, {type, wrap}, 
			       {format, external}, {size, {50000, 5}}]),
    log("proxy_starting"),
    bandwidth:start_link(),
    dns_cache:start_link(),
    start_services(fire_config:lookup(services)),
    spawn_link(fun() -> dynamic_dns() end),
    log("everything started, entering the supervisor loop\n"),
    supervise().

start_services(Services) -> 
    F = fun({dns_proxy, Server}) ->
		Pid = spawn_link(fun() -> dns_proxy:go(Server) end),
		log("~p is a DNS proxy\n", [Pid]);

	   ({registrar, Port, Users}) ->
		Pid = registrar:start_link(Port, Users),
		log("~p is a registrar on ~p\n", [Pid, Port]);

	   ({plain_forward, LPort, Host, RPort, Allowed}) ->
		A = fun(Rx) ->
			    Opt = [binary,{active, false}, {keepalive, true}],
			    {ok, Quad} = dns_cache:lookup(Host),
			    {ok, S} = gen_tcp:connect(Quad, RPort, Opt),
			    spawn(fun() -> loop(Rx, S) end),
			    loop(S, Rx)
		    end,
		Pid = spawn_link(fun() -> teleport(LPort, Allowed, A) end),
		log("~p teleports ~p -> ~p:~p\n", [Pid, LPort, Host, RPort]);

	   (X) ->
		log("ignoring service: ~p\n", [X])
	
	   end,
    io:fwrite("services are ~p\n", [Services]),
    lists:foreach(F, Services).

%% Basically an exit-message logger. Eventually this will include support
%% for hot re-loading the config file.
%% 
supervise() ->
    process_flag(trap_exit, true),
    receive
	X -> log("Supervise got ~p\n", [X])
    after 300 * 1000 ->
	    spawn_link(fun() -> check_connection() end)
    end,
    reflect:supervise().

%%--------------------
log(String) ->
    log("~s", [String]).

log(Format, Args) ->
    String = io_lib:fwrite("~p: ~p ~p: " ++ Format, 
			   [self(), date(), time()| Args]),
    disk_log:balog(proxy, String),
    io:fwrite("~s", [String]).

%%--------------------
%% Dynamic DNS which works with ZoneEdit.
%%
%% See the ZoneEdit FAQ at http://www.zoneedit.com/doc/dynamic.html
%%
%% The Auth here is just a base-64 encoded version of the
%% string "user:password"
dynamic_dns() ->
    {Host, Auth} = fire_config:lookup(dyndns_auth),
    Command = "GET http://dynamic.zoneedit.com/auth/dynamic.html?host="
	++ Host ++ " HTTP/1.0\r\n"
	"User-Agent: reflect/1.0\r\n"
	"Host: dynamic.zoneedit.com\r\n"
	"Accept: */*\r\n"
	"Authorization: Basic " ++ Auth ++ "\r\n\r\n",
    log("Running dynamic DNS\n"),
    {ok, S} = gen_tcp:connect("dynamic.zoneedit.com", 80, 
			      [{active, false}, {packet, line}]),
    ok = gen_tcp:send(S, Command),
    {ok, Reply} = gen_tcp:recv(S, 0),
    case string:tokens(Reply, "\n ") of
	[_, "200"|_] -> ok;
	[_, "401"|_] -> log("Dynamic DNS failed: ~p\n", [Reply])
    end,
    gen_tcp:close(S).

%%--------------------
%% Check whether we're still connected via ADSL. If necessary, run DHCP again.
check_connection() ->
    %% The suicide function is spawned if can_download fails. It reboots
    %% the whole system if we still can't download 15 minutes later.
    Suicide = fun() ->
		      timer:sleep(15 * 60 * 1000),
		      case can_download of 
			  ok -> 
			      log("suicide aborted\n", []),
			      fine;
			  _ ->
			      log("committing suicide\n", []),
			      init:stop()
		      end
	      end,

    F = fun() ->
		case can_download() of
		    ok -> 
			fine;
		    _ -> 
			spawn(Suicide),
			restart_pump(),
			dynamic_dns()
		end
	end,
    spawn_link(F).

restart_pump() ->
    log("restarting pump\n"),
    os:cmd("pump -i " ++ fire_config:lookup(external_if)).

%% Check whether our connection is still up by connecting to a few
%% sites which should be up. We're happy if any of them are up.
%%
%% returns ok | error
can_download() ->
    log("checking connection to Telia\n"),
    Sites = ["www.corelatus.com", "www.telia.com", "www.sunet.se"],
    F = fun(Site) ->
		case gen_tcp:connect(Site, 80, []) of
		    {ok, S} -> 
			gen_tcp:close(S),
			ok;
		    _ ->
			log("can_download: connect to ~s failed\n", [Site]),
			error
		end
	end,
    [H|_] = lists:reverse(lists:sort(lists:map(F, Sites))),
    H.

%%----------------------------------------------------------------------
%% Teleport 
%%
%% Listen_on: the port number we call listen/2 on
%% Bidir: do we allow connections from "outside"?
%% Action: A fun which is called whenever someone connects
%%
teleport(Listen_on, Allowed, Action) ->
    Opt = [{reuseaddr, true}, binary, {active, false}, {keepalive, true}],
    case (catch gen_tcp:listen(Listen_on, Opt)) of
	{ok, L} ->
	    catch accept_loop(Listen_on, L, Allowed, Action),
	    catch gen_tcp:close(L);
	Error ->
	    log("Trying to listen on ~w, got ~w\n", [Listen_on, Error]),
	    timer:sleep(50000)
    end,
    timer:sleep(500),  % keep restart rate reasonable
    reflect:teleport(Listen_on, Allowed, Action).

accept_loop(Source_port, L, Allowed, Action) ->
    case gen_tcp:accept(L) of
	{ok, I} ->
	    case catch connection_allowed(Allowed, I) of
		true -> 
		    ok;
		_X -> 
		    exit(illegal_access)
	    end,
	    F = fun() -> Action(I) end,
	    _Pid = spawn(F),
	    %% REVISIT: following line commented out because of a Netscape
	    %% bug--mail doesn't really get sent if socket dies
            % gen_tcp:controlling_process(I, Pid),
	    accept_loop(Source_port, L, Allowed, Action);
		  
	X ->
	    log("accept returned ~p\n", [X])
    end.

loop(Rx, Tx) ->
    {ok, {Rx_IP, _}} = inet:peername(Rx),
    {ok, {Tx_IP, _}} = inet:peername(Tx),
    case {is_internal_ip_address(Rx_IP), is_internal_ip_address(Tx_IP)} of
	{true, true} ->
	    loop_body(Rx, Tx, {now(), 0}, no_throttle);
	_ ->
	    loop_body(Rx, Tx, {now(), 0}, 0)
    end.

%% Half duplex reflector, does a blocking read on RX. 
%% Copies read data to TX.
%%
%% Keeps track of bandwidth use and possibly throttles it. The throttling
%% is only done on connections which have been up for longer than 10s
loop_body(Rx, Tx, {Then, Bytes}, Delay) ->
    case Delay of
	Integer when is_integer(Integer), Integer > 0 -> timer:sleep(Delay);
	_ -> fine
    end,

    Now = now(),
    Diff = time_diff(Then, Now),
    
    case gen_tcp:recv(Rx, 0) of
	{ok, Bin} ->
	    gen_tcp:send(Tx, Bin),
	    case Diff > 10000 of
		true when is_integer(Delay) ->
		    New_delay = bandwidth:new_delay(Delay, Diff, Bytes),
		    loop_body(Rx, Tx, {Now, size(Bin)}, New_delay);
		_ ->
		    reflect:loop_body(Rx, Tx, {Then, Bytes + size(Bin)}, Delay)
	    end;
		    
	{error, closed} ->
	    kill(Rx, Tx);
	X ->
	    kill(Rx, Tx),
	    log("loop got ~p\n", [X]),
	    die
    end.

%% returns time difference in milliseconds
time_diff({AM, AS, Am}, {BM, BS, Bm}) ->
    ((BM - AM) * 1000000 + (BS - AS)) * 1000 + (Bm - Am) div 1000.

%% A connection is allowed if
%%
%%       - the list of allowed IP addresses is ".any"
%%
%%   or  - the ".registered" option is there and the IP address has
%%         been registered.
%%
%%   or  - it's an internal access
%%
%% Return: true or false
connection_allowed([".any"], _Incoming_socket) ->
    true;

connection_allowed([".registered"], I) -> 
    {ok, {Remote_IP, _Port}} = inet:peername(I),
    registrar:is_registered(Remote_IP);

%% This assumes that internal IP addresses are on the internal interface.
%% You need to make sure that this is always true, e.g. by setting up an
%% IP packet filter.
connection_allowed("", Incoming_socket) -> 
    {ok, {IP, _Port}} = inet:peername(Incoming_socket),
    case is_internal_ip_address(IP) of
	true -> true;
	false ->
	    log("rejecting from outside (~p).\n", [IP]), 
	    false
    end;

%% Is the connection in the IP whitelist?
connection_allowed([Host|T], I) -> 
    {ok, {Remote, _Port}} = inet:peername(I),
    case inet:getaddr(Host, inet) of
	{ok, Remote} -> true;
	_ -> 
	    connection_allowed(T, I)
    end.

%% Return: true | false
is_internal_ip_address({A,B,C,D}) ->
    {Net, Mask} = fire_config:lookup(int_net),
    <<Peer:32>> = <<A,B,C,D>>,
    (Peer band Mask) == Net.

kill(S) -> catch(gen_tcp:close(S)).
kill(Tx, Rx) ->
    kill(Tx), 
    kill(Rx).

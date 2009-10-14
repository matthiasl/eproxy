%% A very simple DNS proxy.
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
-module(dns_proxy).
-export([go/1, loop/4]).

go(DNS_server) ->
    {ok, Inside} = gen_udp:open(dns_portno(), [binary]),
    {ok, Outside} = gen_udp:open(0, [binary]),
    loop(Inside, Outside, dict:new(), DNS_server).

dns_portno() ->
     53.

%% Outstanding: dict: Id -> {Ip, Port}
loop(Inside, Outside, Outstanding, DNS_server) ->
    New_dict = 
	receive
	    {udp, Inside, IP, Port, Packet} when size(Packet) > 2 ->
		gen_udp:send(Outside, DNS_server, dns_portno(), Packet),
%%		io:fwrite("got DNS packet from inside: ~p\n", [Packet]),
		<<Id:16, _/binary>> = Packet,
		dict:store(Id, {IP, Port}, Outstanding);

	    {udp, Outside, IP, _Portno, Packet} 
	    when size(Packet) > 2,
	    DNS_server == IP ->
		<<Id:16, _/binary>> = Packet,
		case dict:find(Id, Outstanding) of
		    {ok, {Dest_IP, Dest_port}} ->
			gen_udp:send(Inside, Dest_IP, Dest_port, Packet),
			dict:erase(Id, Outstanding);
		    _ ->
			io:fwrite("ignoring DNS reply: ~p\n", [Packet]),
			Outstanding
		end;
	X ->
	    io:fwrite("ignoring message: ~p\n", [X]),
	    Outstanding
    end,
    dns_proxy:loop(Inside, Outside, New_dict, DNS_server).

    

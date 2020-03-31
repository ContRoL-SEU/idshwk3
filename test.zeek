global temp : table[addr] of set[string];
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local ip = c$id$orig_h;
	if(c$http?$user_agent)
	{
		local agent = to_lower(c$http$user_agent);
		if(ip in temp)
		{
			add (temp[ip])[agent];
		}
		else
		{
			temp[ip] = set(agent);
		}
	}
}

event zeek_done()
{
	for(ip in temp)
	{
		if(|temp[ip]|>=3)
		{
			print(addr_to_uri(ip) + " is a proxy");
		}
	}
}

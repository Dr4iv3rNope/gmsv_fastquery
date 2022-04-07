require("fastquery")

fastquery.EnableLuaModifyCachedReplyInfo(true) -- enables FastQueryBuildReplyInfo hook
fastquery.EnableInfoCache(true) -- enable A2S_INFO response cache
fastquery.SetInfoCacheTime(5) -- seconds for cache to live (default is 5 seconds)

hook.Add("FastQueryBuildReplyInfo", "A2S_INFO cache modifier", function(info)
	-- string	info["server_name"]:		server's name
	-- string	info["map_name"]:			current map
	-- string	info["game_dir"]:			game directory. You shouldn't change that
	-- string	info["game_desc"]:			game description
	-- number	info["appid"]:				server appid. You shouldn't change that
	-- number	info["num_clients"]:		player count
	-- number	info["max_players"]:		max players count
	-- number	info["num_fake_clients"]:	bot count
	-- boolean	info["has_password"]:		is server has password? You shouldn't change that
	-- boolean	info["vac_secure"]:			is server vac secured? You shouldn't change that
	-- string	info["game_version"]:		game version. You shouldn't change that
	-- number	info["udp_port"]:			server udp port. You shouldn't change that
	-- string	info["steamid"]:			steamid of GSLT creator. You shouldn't change that
	-- string	info["tags"]:				garry's mod server tags

	return {
		server_name = "My server",
		map_name = "Map is: " .. info.map_name
	}
end)

-- Force refresh of A2S_INFO cache.
-- In this example will call FastQueryBuildReplyInfo hook.
fastquery.RefreshInfoCache()


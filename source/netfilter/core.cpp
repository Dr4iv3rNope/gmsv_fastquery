#include "core.hpp"

#include <GarrysMod/FactoryLoader.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <Platform.hpp>

#include <detouring/classproxy.hpp>
#include <detouring/hook.hpp>

#include <bitbuf.h>
#include <checksum_sha1.h>
#include <dbg.h>
#include <eiface.h>
#include <filesystem_stdio.h>
#include <game/server/iplayerinfo.h>
#include <iserver.h>
#include <steam/steam_gameserver.h>
#include <threadtools.h>
#include <utlvector.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <queue>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define FASTQUERY_CALLING_CONVENTION __stdcall

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <processthreadsapi.h>
#include <windows.h>

using ssize_t = int32_t;
using recvlen_t = int32_t;

#elif defined SYSTEM_POSIX

#define FASTQUERY_CALLING_CONVENTION

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined SYSTEM_LINUX

#include <sys/prctl.h>

#elif defined SYSTEM_MACOSX

#include <pthread.h>

#endif

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

struct netsocket_t {
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
};

namespace netfilter {
static GarrysMod::Lua::ILuaInterface* lua_interface = nullptr;

class Core {
private:
	struct server_tags_t {
		std::string gm;
		std::string gmws;
		std::string gmc;
		std::string loc;
		std::string ver;
	};

public:
	struct packet_t {
		packet_t() : address(), address_size(sizeof(address)) {}

		sockaddr_in address;
		socklen_t address_size;
		std::vector<uint8_t> buffer;
	};

	explicit Core(const char *game_version)
			: server(InterfacePointers::Server()) {

		if (server == nullptr) {
			throw std::runtime_error("failed to dereference IServer");
		}

		if (!server_loader.IsValid()) {
			throw std::runtime_error("unable to get server factory");
		}

		ICvar *icvar = InterfacePointers::Cvar();
		if (icvar != nullptr) {
			sv_visiblemaxplayers = icvar->FindVar("sv_visiblemaxplayers");
			sv_location = icvar->FindVar("sv_location");
		}

		if (sv_visiblemaxplayers == nullptr) {
			Warning("[FastQuery] Failed to get \"sv_visiblemaxplayers\" convar!\n");
		}

		if (sv_location == nullptr) {
			Warning("[FastQuery] Failed to get \"sv_location\" convar!\n");
		}

		gamedll = InterfacePointers::ServerGameDLL();
		if (gamedll == nullptr) {
			throw std::runtime_error("failed to load required IServerGameDLL interface");
		}

		engine_server = InterfacePointers::VEngineServer();
		if (engine_server == nullptr) {
			throw std::runtime_error("failed to load required IVEngineServer interface");
		}

		filesystem = InterfacePointers::FileSystem();
		if (filesystem == nullptr) {
			throw std::runtime_error("failed to initialize IFileSystem");
		}

		const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket = FunctionPointers::GMOD_GetNetSocket();
		if (GetNetSocket != nullptr) {
			const netsocket_t *net_socket = GetNetSocket(1);
			if (net_socket != nullptr) {
				game_socket = net_socket->hUDP;
			}
		}

		if (game_socket == INVALID_SOCKET) {
			throw std::runtime_error("got an invalid server socket");
		}

		if (!recvfrom_hook.Enable()) {
			throw std::runtime_error("failed to detour recvfrom");
		}

		threaded_socket_execute = true;
		threaded_socket_handle = CreateSimpleThread(PacketReceiverThread, this);
		if (threaded_socket_handle == nullptr) {
			throw std::runtime_error("unable to create thread");
		}

		BuildStaticReplyInfo(game_version);
	}

	~Core() {
		if (threaded_socket_handle != nullptr) {
			threaded_socket_execute = false;
			ThreadJoin(threaded_socket_handle);
			ReleaseThreadHandle(threaded_socket_handle);
			threaded_socket_handle = nullptr;
		}

		recvfrom_hook.Destroy();
	}

	Core(const Core &) = delete;
	Core(Core &&) = delete;

	Core &operator=(const Core &) = delete;
	Core &operator=(Core &&) = delete;

	void BuildStaticReplyInfo(const char *game_version) {
		reply_info.game_desc = gamedll->GetGameDescription();

		{
			reply_info.game_dir.resize(256);
			engine_server->GetGameDir(
					&reply_info.game_dir[0],
					static_cast<int32_t>(reply_info.game_dir.size()));
			reply_info.game_dir.resize(std::strlen(reply_info.game_dir.c_str()));

			size_t pos = reply_info.game_dir.find_last_of("\\/");
			if (pos != std::string::npos) {
				reply_info.game_dir.erase(0, pos + 1);
			}
		}

		reply_info.max_clients = server->GetMaxClients();

		reply_info.udp_port = server->GetUDPPort();

		{
			const IGamemodeSystem::Information &gamemode =
					dynamic_cast<CFileSystem_Stdio *>(filesystem)->Gamemodes()->Active();

			if (!gamemode.name.empty()) {
				reply_info.tags.gm = gamemode.name;
			} else {
				reply_info.tags.gm.clear();
			}

			if (gamemode.workshopid != 0) {
				reply_info.tags.gmws = std::to_string(gamemode.workshopid);
			} else {
				reply_info.tags.gmws.clear();
			}

			if (!gamemode.category.empty()) {
				reply_info.tags.gmc = gamemode.category;
			} else {
				reply_info.tags.gmc.clear();
			}

			if (game_version != nullptr) {
				reply_info.tags.ver = game_version;
			}
		}

		{
			FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
			if (file == nullptr) {
				reply_info.game_version = default_game_version;
				DevWarning("[FastQuery] Error opening steam.inf\n");
				return;
			}

			std::array<char, 256> buff{};
			bool failed =
					filesystem->ReadLine(buff.data(), buff.size(), file) == nullptr;
			filesystem->Close(file);
			if (failed) {
				reply_info.game_version = default_game_version;
				DevWarning("[FastQuery] Failed reading steam.inf\n");
				return;
			}

			reply_info.game_version = &buff[13];

			size_t pos = reply_info.game_version.find_first_of("\r\n");
			if (pos != std::string::npos) {
				reply_info.game_version.erase(pos);
			}
		}
	}

	static std::string ConcatenateTags(const server_tags_t &tags) {
		std::string strtags;

		if (!tags.gm.empty()) {
			strtags += "gm:";
			strtags += tags.gm;
		}

		if (!tags.gmws.empty()) {
			strtags += strtags.empty() ? "gmws:" : " gmws:";
			strtags += tags.gmws;
		}

		if (!tags.gmc.empty()) {
			strtags += strtags.empty() ? "gmc:" : " gmc:";
			strtags += tags.gmc;
		}

		if (!tags.loc.empty()) {
			strtags += strtags.empty() ? "loc:" : " loc:";
			strtags += tags.loc;
		}

		if (!tags.ver.empty()) {
			strtags += strtags.empty() ? "ver:" : " ver:";
			strtags += tags.ver;
		}

		return strtags;
	}

	struct cached_reply_info {
		const char* server_name;
		const char* map_name;
		const char* game_dir;
		const char* game_desc;
		int32_t appid;
		int32_t num_clients;
		int32_t max_players;
		int32_t num_fake_clients;
		bool has_password;
		bool vac_secure;
		const char* game_version;
		int32_t udp_port;
		uint64_t steamid;
		std::string tags;
	};

	bool LuaModifyCachedReplyInfo(cached_reply_info& info) {
		lua_interface->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua_interface->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua_interface->ErrorNoHalt("[FastQuery:LuaModifyReplyInfo] Global hook is not a table!\n");
			lua_interface->Pop(2);
			return false;
		}

		lua_interface->GetField(-1, "Run");
		lua_interface->Remove(-2);
		if (!lua_interface->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua_interface->ErrorNoHalt("[FastQuery:LuaModifyReplyInfo] Global hook.Run is not a function!\n");
			lua_interface->Pop(2);
			return false;
		}

		lua_interface->PushString("FastQueryBuildReplyInfo");

		lua_interface->CreateTable();

		lua_interface->PushString(info.server_name);
		lua_interface->SetField(-2, "server_name");

		lua_interface->PushString(info.map_name);
		lua_interface->SetField(-2, "map_name");

		lua_interface->PushString(info.game_dir);
		lua_interface->SetField(-2, "game_dir");

		lua_interface->PushString(info.game_desc);
		lua_interface->SetField(-2, "game_desc");

		lua_interface->PushNumber(info.appid);
		lua_interface->SetField(-2, "appid");

		lua_interface->PushNumber(info.num_clients);
		lua_interface->SetField(-2, "num_clients");

		lua_interface->PushNumber(info.max_players);
		lua_interface->SetField(-2, "max_players");

		lua_interface->PushNumber(info.num_fake_clients);
		lua_interface->SetField(-2, "num_fake_clients");

		lua_interface->PushBool(info.has_password);
		lua_interface->SetField(-2, "has_password");

		lua_interface->PushBool(info.vac_secure);
		lua_interface->SetField(-2, "vac_secure");

		lua_interface->PushString(info.game_version);
		lua_interface->SetField(-2, "game_version");

		lua_interface->PushNumber(info.udp_port);
		lua_interface->SetField(-2, "udp_port");

		lua_interface->PushNumber(info.steamid);
		lua_interface->SetField(-2, "steamid");

		lua_interface->PushString(info.tags.c_str());
		lua_interface->SetField(-2, "tags");

		bool modified = false;

		if (lua_interface->PCall(2, 1, 0) != 0) {
			lua_interface->ErrorNoHalt("\n[FastQuery:LuaModifyReplyInfo] %s\n\n", lua_interface->GetString(-1));
		} else {
			if (lua_interface->IsType(-1, GarrysMod::Lua::Type::TABLE)) {
				modified = true;

				lua_interface->GetField(-1, "server_name");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.server_name = lua_interface->GetString(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "map_name");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.map_name = lua_interface->GetString(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "game_dir");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.game_dir = lua_interface->GetString(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "game_desc");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.game_desc = lua_interface->GetString(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "appid");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.appid = static_cast<int32_t>(lua_interface->GetNumber(-1));
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "num_clients");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.num_clients = static_cast<int32_t>(lua_interface->GetNumber(-1));
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "max_players");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.max_players = static_cast<int32_t>(lua_interface->GetNumber(-1));
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "num_fake_clients");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.num_fake_clients = static_cast<int32_t>(lua_interface->GetNumber(-1));
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "has_password");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::BOOL))
					info.has_password = lua_interface->GetBool(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "vac_secure");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::BOOL))
					info.vac_secure = lua_interface->GetBool(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "game_version");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.game_version = lua_interface->GetString(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "udp_port");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.udp_port = static_cast<int32_t>(lua_interface->GetNumber(-1));
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "steamid");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::NUMBER))
					info.steamid = lua_interface->GetNumber(-1);
				lua_interface->Pop(1);

				lua_interface->GetField(-1, "tags");
				if (lua_interface->IsType(-1, GarrysMod::Lua::Type::STRING))
					info.tags = lua_interface->GetString(-1);
				lua_interface->Pop(1);
			}
		}

		lua_interface->Pop(1);
		return modified;
	}

	void LuaTick()
	{
		if (lua_thread_data.build_info)
		{
			lua_thread_data.build_info = false;

			BuildReplyInfo();
		}
	}

	void BuildReplyInfo() {
		DevWarning("[FastQuery] Building reply info\n");

		cached_reply_info info;

		info.server_name = server->GetName();
		info.map_name = server->GetMapName();
		info.game_dir = reply_info.game_dir.c_str();
		info.game_desc = reply_info.game_desc.c_str();
		info.appid = engine_server->GetAppID();
		info.num_clients = server->GetNumClients();

		info.max_players = sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt() : -1;

		if (info.max_players <= 0 || info.max_players > reply_info.max_clients)
			info.max_players = reply_info.max_clients;

		info.num_fake_clients = server->GetNumFakeClients();
		info.has_password = server->GetPassword() != nullptr;

		if (gameserver == nullptr)
			gameserver = SteamGameServer();

		info.vac_secure = false;

		if (gameserver != nullptr)
			info.vac_secure = gameserver->BSecure();

		info.game_version = reply_info.game_version.c_str();
		info.udp_port = reply_info.udp_port;

		const CSteamID *sid = engine_server->GetGameServerSteamID();
		info.steamid = sid != nullptr ? sid->ConvertToUint64() : 0;

		info.tags = ConcatenateTags(reply_info.tags);

		if (lua_modify_reply_info)
			LuaModifyCachedReplyInfo(info);

		if (sv_location != nullptr)
			reply_info.tags.loc = sv_location->GetString();
		else
			reply_info.tags.loc.clear();

		bool has_tags = !info.tags.empty();

		info_cache_packet.Reset();

		info_cache_packet.WriteLong(-1);  // connectionless packet header
		info_cache_packet.WriteByte('I'); // packet type is always 'I'
		info_cache_packet.WriteByte(default_proto_version);
		info_cache_packet.WriteString(info.server_name);
		info_cache_packet.WriteString(info.map_name);
		info_cache_packet.WriteString(info.game_dir);
		info_cache_packet.WriteString(info.game_desc);
		info_cache_packet.WriteShort(info.appid);
		info_cache_packet.WriteByte(info.num_clients);
		info_cache_packet.WriteByte(info.max_players);
		info_cache_packet.WriteByte(info.num_fake_clients);
		info_cache_packet.WriteByte('d'); // dedicated server identifier
		info_cache_packet.WriteByte(operating_system_char);
		info_cache_packet.WriteByte(info.has_password ? 1 : 0);
		info_cache_packet.WriteByte(static_cast<int>(info.vac_secure));
		info_cache_packet.WriteString(info.game_version);
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte(0x80 | 0x10 | (has_tags ? 0x20 : 0x00) | 0x01);
		info_cache_packet.WriteShort(info.udp_port);
		info_cache_packet.WriteLongLong(static_cast<int64_t>(info.steamid));

		if (has_tags)
			info_cache_packet.WriteString(info.tags.c_str());

		info_cache_packet.WriteLongLong(info.appid);
	}

	void SetInfoCacheState(const bool enabled) { info_cache_enabled = enabled; }

	void SetInfoCacheTime(const uint32_t time) { info_cache_time = time; }

	void SetLuaModifyReplyInfoEnabled(bool enable) { lua_modify_reply_info = enable; }

	static std::unique_ptr<Core> Singleton;

private:
	struct reply_info_t {
		std::string game_dir;
		std::string game_version;
		std::string game_desc;
		int32_t max_clients = 0;
		int32_t udp_port = 0;
		server_tags_t tags;
	};

	enum class PacketType { Invalid = -1, Good, Info };

	using recvfrom_t = ssize_t(FASTQUERY_CALLING_CONVENTION *)(
			SOCKET, void *, recvlen_t, int32_t, sockaddr *, socklen_t *);

#if defined SYSTEM_WINDOWS

	static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

	static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

	static constexpr char operating_system_char = 'm';

#endif

	static constexpr size_t threaded_socket_max_buffer = 8192;
	static constexpr size_t threaded_socket_max_queue = 1000;

	static constexpr std::string_view default_game_version = "2020.10.14";
	static constexpr uint8_t default_proto_version = 17;

	// Max size needed to contain a Steam authentication key (both server and
	// client)
	static constexpr int16_t STEAM_KEYSIZE = 2048;

	// Connection from client is using a WON authenticated certificate
	static constexpr int32_t PROTOCOL_AUTHCERTIFICATE = 0x01;
	// Connection from client is using hashed CD key because WON comm. channel was
	// unreachable
	static constexpr int32_t PROTOCOL_HASHEDCDKEY = 0x02;
	// Steam certificates
	static constexpr int32_t PROTOCOL_STEAM = 0x03;
	// Last valid protocol
	static constexpr int32_t PROTOCOL_LASTVALID = 0x03;

	static constexpr int32_t MAX_RANDOM_RANGE = 0x7FFFFFFFUL;

	IServer *server = nullptr;

	ISteamGameServer *gameserver = nullptr;

	SourceSDK::FactoryLoader icvar_loader = SourceSDK::FactoryLoader("vstdlib");
	ConVar *sv_visiblemaxplayers = nullptr;
	ConVar *sv_location = nullptr;

	SourceSDK::ModuleLoader dedicated_loader =
			SourceSDK::ModuleLoader("dedicated");
	SourceSDK::FactoryLoader server_loader = SourceSDK::FactoryLoader("server");

#ifdef PLATFORM_WINDOWS

	Detouring::Hook recvfrom_hook = Detouring::Hook(
			"ws2_32", "recvfrom", reinterpret_cast<void *>(recvfrom_detour));

#else

	Detouring::Hook recvfrom_hook =
			Detouring::Hook("recvfrom", reinterpret_cast<void *>(recvfrom_detour));

#endif

	SOCKET game_socket = INVALID_SOCKET;

	bool threaded_socket_execute = true;
	ThreadHandle_t threaded_socket_handle = nullptr;
	std::queue<packet_t> threaded_socket_queue;
	CThreadFastMutex threaded_socket_mutex;

	bool info_cache_enabled = false;
	bool lua_modify_reply_info{false};
	reply_info_t reply_info;
	std::array<char, 1024> info_cache_buffer{};
	bf_write info_cache_packet = bf_write(
			info_cache_buffer.data(), static_cast<int32_t>(info_cache_buffer.size()));
	uint32_t info_cache_last_update = 0;
	uint32_t info_cache_time = 5;
	struct {
		bool build_info = false;
	} lua_thread_data;

	IServerGameDLL *gamedll = nullptr;
	IVEngineServer *engine_server = nullptr;
	IFileSystem *filesystem = nullptr;

	static inline const char *IPToString(const in_addr &addr) {
		static std::array<char, INET_ADDRSTRLEN> buffer{};
		const char *str = inet_ntop(AF_INET, &addr, buffer.data(), buffer.size());
		if (str == nullptr) {
			return "unknown";
		}

		return str;
	}

	PacketType SendInfoCache(const sockaddr_in &from, uint32_t time) {
		if (time - info_cache_last_update >= info_cache_time) {
			lua_thread_data.build_info = true;
			info_cache_last_update = time;
		}

		sendto(
			game_socket,
			reinterpret_cast<char *>(info_cache_packet.GetData()),
			info_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
		);

		return PacketType::Invalid; // we've handled it
	}

	PacketType HandleInfoQuery(const sockaddr_in &from) {
		DevWarning("[FastQuery] Handling info query from %s\n", IPToString(from.sin_addr));

		if (info_cache_enabled) {
			return SendInfoCache(from, static_cast<uint32_t>(Plat_FloatTime()));
		}

		return PacketType::Good;
	}

	PacketType ClassifyPacket(const uint8_t *data, int32_t len, const sockaddr_in &from) const {
		if (len == 0) {
			DevWarning("[FastQuery] Bad OOB! len: %d from %s\n", len, IPToString(from.sin_addr));
			return PacketType::Invalid;
		}

		if (len < 5) {
			return PacketType::Good;
		}

		bf_read packet(data, len);
		const auto channel = static_cast<int32_t>(packet.ReadLong());
		if (channel == -2) {
			DevWarning("[FastQuery] Bad OOB! len: %d, channel: 0x%X from %s\n", len, channel, IPToString(from.sin_addr));
			return PacketType::Invalid;
		}

		if (channel != -1) {
			return PacketType::Good;
		}

		return static_cast<uint8_t>(packet.ReadByte()) == 'T'
			? PacketType::Info
			: PacketType::Good;
	}

	static int32_t HandleNetError(int32_t value) {
		if (value == -1) {

#if defined SYSTEM_WINDOWS

			WSASetLastError(WSAEWOULDBLOCK);

#elif defined SYSTEM_POSIX

			errno = EWOULDBLOCK;

#endif
		}

		return value;
	}

	bool IsPacketQueueFull() {
		AUTO_LOCK(threaded_socket_mutex);
		return threaded_socket_queue.size() >= threaded_socket_max_queue;
	}

	bool PopPacketFromQueue(packet_t &p) {
		AUTO_LOCK(threaded_socket_mutex);

		if (threaded_socket_queue.empty()) {
			return false;
		}

		p = std::move(threaded_socket_queue.front());
		threaded_socket_queue.pop();
		return true;
	}

	void PushPacketToQueue(packet_t &&p) {
		AUTO_LOCK(threaded_socket_mutex);
		threaded_socket_queue.emplace(std::move(p));
	}

	ssize_t ReceiveAndAnalyzePacket(SOCKET s, void *buf, recvlen_t buflen,
																	int32_t flags, sockaddr *from,
																	socklen_t *fromlen) {
		auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
		if (trampoline == nullptr) {
			return -1;
		}

		const ssize_t len = trampoline(s, buf, buflen, flags, from, fromlen);
		if (len == -1) {
			return -1;
		}

		const uint8_t *buffer = reinterpret_cast<uint8_t *>(buf);
		const sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>(from);

		PacketType type = ClassifyPacket(buffer, len, infrom);
		if (type == PacketType::Info) {
			type = HandleInfoQuery(infrom);
		}

		return type != PacketType::Invalid ? len : -1;
	}

	ssize_t HandleDetour(SOCKET s, void *buf, recvlen_t buflen, int32_t flags,
											 sockaddr *from, socklen_t *fromlen) {
		if (s != game_socket) {
			auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
			return trampoline != nullptr
				? trampoline(s, buf, buflen, flags, from, fromlen)
				: -1;
		}

		packet_t p;
		const bool has_packet = PopPacketFromQueue(p);
		if (!has_packet) {
			return HandleNetError(-1);
		}

		const ssize_t len = (std::min)(
			static_cast<ssize_t>(p.buffer.size()),
			static_cast<ssize_t>(buflen)
		);
		p.buffer.resize(static_cast<size_t>(len));
		std::copy(p.buffer.begin(), p.buffer.end(), static_cast<uint8_t *>(buf));

		const socklen_t addrlen = (std::min)(*fromlen, p.address_size);
		std::memcpy(from, &p.address, static_cast<size_t>(addrlen));
		*fromlen = addrlen;

		return len;
	}

	static ssize_t FASTQUERY_CALLING_CONVENTION
	recvfrom_detour(SOCKET s, void *buf, recvlen_t buflen, int32_t flags,
									sockaddr *from, socklen_t *fromlen) {
		return Singleton->HandleDetour(s, buf, buflen, flags, from, fromlen);
	}

	uintp HandleThread() {
		while (threaded_socket_execute) {
			if (IsPacketQueueFull()) {
				DevWarning("[FastQuery] Packet queue is full, sleeping for 100ms\n");
				ThreadSleep(100);
				continue;
			}

			fd_set readables;
			FD_ZERO(&readables);
			// NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
			FD_SET(game_socket, &readables);
			timeval timeout = {0, 100000};
			const int32_t res = select(
				static_cast<int32_t>(game_socket + 1),
				&readables,
				nullptr,
				nullptr,
				&timeout
			);

			if (res == -1 || !FD_ISSET(game_socket, &readables)) {
				continue;
			}

			packet_t p;
			p.buffer.resize(threaded_socket_max_buffer);
			const ssize_t len = ReceiveAndAnalyzePacket(
					game_socket, p.buffer.data(),
					static_cast<recvlen_t>(threaded_socket_max_buffer), 0,
					reinterpret_cast<sockaddr *>(&p.address), &p.address_size);
			if (len == -1) {
				continue;
			}

			p.buffer.resize(static_cast<size_t>(len));

			PushPacketToQueue(std::move(p));
		}

		return 0;
	}

	static uintp PacketReceiverThread(void *param) {
#ifdef SYSTEM_WINDOWS

		SetThreadDescription(GetCurrentThread(),
												 L"FastQuery packet receiver/analyzer");

#elif SYSTEM_LINUX

		prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("FastQuery"), 0, 0,
					0);

#elif SYSTEM_MACOSX

		pthread_setname_np("FastQuery");

#endif

		return static_cast<Core *>(param)->HandleThread();
	}
};

std::unique_ptr<Core> Core::Singleton;

LUA_FUNCTION_STATIC(EnableInfoCache) {
	LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
	Core::Singleton->SetInfoCacheState(LUA->GetBool(1));
	return 0;
}

LUA_FUNCTION_STATIC(SetInfoCacheTime) {
	LUA->CheckType(1, GarrysMod::Lua::Type::Number);
	Core::Singleton->SetInfoCacheTime(static_cast<uint32_t>(LUA->GetNumber(1)));
	return 0;
}

LUA_FUNCTION_STATIC(RefreshInfoCache) {
	Core::Singleton->BuildStaticReplyInfo(nullptr);
	Core::Singleton->BuildReplyInfo();
	return 0;
}

LUA_FUNCTION_STATIC(EnableLuaModifyCachedReplyInfo)
{
	LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
	Core::Singleton->SetLuaModifyReplyInfoEnabled(LUA->GetBool(1));
	return 0;
}

LUA_FUNCTION_STATIC(Tick) {
	Core::Singleton->LuaTick();
	return 0;
}

void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
	LUA->GetField(GarrysMod::Lua::INDEX_GLOBAL, "VERSION");
	const char *game_version = LUA->CheckString(-1);

	bool errored = false;
	try {
		Core::Singleton = std::make_unique<Core>(game_version);
	} catch (const std::exception &e) {
		errored = true;
		LUA->PushString(e.what());
	}

	if (errored) {
		LUA->Error();
	}

	LUA->Pop(1);

	lua_interface = reinterpret_cast<GarrysMod::Lua::ILuaInterface*>(LUA);

	LUA->PushCFunction(EnableInfoCache);
	LUA->SetField(-2, "EnableInfoCache");

	LUA->PushCFunction(SetInfoCacheTime);
	LUA->SetField(-2, "SetInfoCacheTime");

	LUA->PushCFunction(RefreshInfoCache);
	LUA->SetField(-2, "RefreshInfoCache");

	LUA->PushCFunction(EnableLuaModifyCachedReplyInfo);
	LUA->SetField(-2, "EnableLuaModifyCachedReplyInfo");

	lua_interface->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
	if (!lua_interface->IsType(-1, GarrysMod::Lua::Type::TABLE))
	{
		lua_interface->Pop(2);
		lua_interface->Error("[FastQuery] Global hook is not a table!\n");
		return;
	}

	lua_interface->GetField(-1, "Add");
	lua_interface->Remove(-2);
	if (!lua_interface->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
	{
		lua_interface->Pop(2);
		lua_interface->Error("[FastQuery] Global hook.Add is not a function!\n");
		return;
	}

	lua_interface->PushString("Tick");
	lua_interface->PushString("__fastqueryThreadSync");
	lua_interface->PushCFunction(Tick);

	if (lua_interface->PCall(3, 0, 0) != 0)
	{
		std::string err_msg = "[FastQuery:LuaModifyReplyInfo] hook.Add failed: ";
		err_msg += lua_interface->GetString(-1);
		err_msg += "\n\n";

		lua_interface->Pop(1);
		lua_interface->Error(err_msg.c_str());
	}
}

void Deinitialize() {
	Core::Singleton.reset();
}
} // namespace netfilter

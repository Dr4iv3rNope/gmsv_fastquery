#include "netfilter/core.hpp"

#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <Platform.hpp>

#include <iserver.h>

#include <cstdint>
#include <string>

namespace global {
	static IServer *server = nullptr;

	LUA_FUNCTION_STATIC(GetClientCount) {
		LUA->PushNumber(server->GetClientCount());
		return 1;
	}

	static void PreInitialize(GarrysMod::Lua::ILuaBase *LUA) {
		server = InterfacePointers::Server();
		if (server == nullptr) {
			LUA->ThrowError("failed to dereference IServer");
		}

		LUA->CreateTable();

		LUA->PushCFunction(GetClientCount);
		LUA->SetField(-2, "GetClientCount");
	}

	static void Initialize(GarrysMod::Lua::ILuaBase *LUA) {
		LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "fastquery");
	}

	static void Deinitialize(GarrysMod::Lua::ILuaBase *LUA) {
		LUA->PushNil();
		LUA->SetField(GarrysMod::Lua::INDEX_GLOBAL, "fastquery");
	}
} // namespace global

GMOD_MODULE_OPEN() {
	global::PreInitialize(LUA);
	netfilter::Initialize(LUA);
	global::Initialize(LUA);
	return 1;
}

GMOD_MODULE_CLOSE() {
	netfilter::Deinitialize();
	global::Deinitialize(LUA);
	return 0;
}

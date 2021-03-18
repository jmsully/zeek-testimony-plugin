// See the file  in the main distribution directory for copyright.

#include "Source.h"
#include "Plugin.h"
#include <zeek/plugin/Plugin.h>
#include <zeek/iosource/Component.h>

namespace ZEEK_PLUGIN_NS { namespace Zeek_Testimony { Plugin plugin; } }

using namespace ZEEK_PLUGIN_NS::Zeek_Testimony;
using namespace ZEEK_IOSOURCE_NS;


ZEEK_PLUGIN_NS::Configuration Plugin::Configure()
		{
		AddComponent(new PktSrcComponent("TestimonyReader", "testimony", PktSrcComponent::LIVE, testimony::TestimonySource::Instantiate));

		ZEEK_PLUGIN_NS::Configuration config;
		config.name = "Zeek::Testimony";
		config.description = "Packet acquisition from Google Testimony Unix socket";
		return config;
		}

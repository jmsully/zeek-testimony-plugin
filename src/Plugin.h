#include <zeek/plugin/Plugin.h>
#include "zeek-compat.h"

namespace ZEEK_PLUGIN_NS {
namespace Zeek_Testimony {

class Plugin : public ZEEK_PLUGIN_NS::Plugin
{
protected:
	virtual ZEEK_PLUGIN_NS::Configuration Configure();
};

extern Plugin plugin;

}
}

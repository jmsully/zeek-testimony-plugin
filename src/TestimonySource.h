// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <iosource/PktSrc.h>
#include "zeek-compat.h"
#include "TemporaryQueueWriter/TemporaryQueueWriter.h"

extern "C" {
#include <testimony.h>
}

#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <sys/types.h> // for u_char

namespace ZEEK_IOSOURCE_NS::testimony {

class TestimonySource : public ZEEK_IOSOURCE_NS::PktSrc {
public:
	TestimonySource(const std::string& path, bool is_live)
		{
		props.path = path;
		props.is_live = is_live;
		curr_packet = NULL;
		running = true;
		}
	~TestimonySource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

	void AddPacketsToTemporaryQueue();

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;
	bool ExtractNextPacket(Packet* pkt) override;
	void DoneWithPacket() override;
	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;

private:
	void OpenLive();

	::testimony td;
	::testimony_iter td_iter;
	timeval curr_timeval;
	tpacket3_hdr *curr_packet;
	std::queue<tpacket3_hdr *> packets;
	std::queue<tpacket3_hdr *> temp_packets;

	std::atomic<bool> running;
	std::mutex queue_access_mutex;
	TemporaryQueueWriter *temporary_queue_writer;

	Properties props;
	Stats stats;
};

} //namespace iosource

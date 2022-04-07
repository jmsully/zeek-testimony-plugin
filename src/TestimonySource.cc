// See the file  in the main distribution directory for copyright.

#include <zeek/zeek-config.h>

#include "TestimonySource.h"
#include <zeek/iosource/Packet.h>
#include <zeek/iosource/BPF_Program.h>

#include <unistd.h>

#include <zeek/Event.h>

using namespace ZEEK_IOSOURCE_NS::testimony;

TestimonySource::~TestimonySource()
	{
	Close();
	}

void TestimonySource::Open()
	{
	OpenLive();
	}

void TestimonySource::Close()
	{
	//temporary_queue_writer will be deleted automatically by thread manager
	testimony_close(td);
	Closed();
	}

void TestimonySource::OpenLive()
	{
	int res;
	const char *fanout_str = getenv("TESTIMONY_FANOUT_ID");
	uint32_t fanout_id;

	res = testimony_connect(&td, props.path.c_str());
	if ( res < 0 )
		{
		Error("testimony_connect: " + std::string(strerror(-res)));
		return;
		}

	if ( fanout_str )
		{
		sscanf(fanout_str, "%u", &fanout_id);
		testimony_conn(td)->fanout_index = fanout_id;
		}

	res = testimony_init(td);
	if ( res < 0 )
		{
		Error("testimony_init: " + std::string(testimony_error(td)) + strerror(-res));
		return;
		}

	testimony_iter_init(&td_iter);

	props.selectable_fd = -1;

	props.link_type = DLT_EN10MB;
	props.is_live = true;

	Opened(props);
	}

bool TestimonySource::ExtractNextPacket(Packet* pkt)
	{
		const u_char *data;
		struct timeval tmp_timeval;
		const tpacket3_hdr *packet;


		while (true)
		{

		if ( (packet = testimony_iter_next(td_iter)) == NULL ) {
			testimony_return_block(td, block);
			int res = testimony_get_block(td, 1000, &block);
			if ( res == 0 && !block ) {
				// Timeout
				continue;
			}
			if ( res < 0 )
			{
				//Error("testimony_get_block:" + std::string(testimony_error(td)) + strerror(-res));
				return false;
				Close();
			}

			testimony_iter_reset(td_iter, block);
		}
		else	{
			// Queue the packet
			
			tmp_timeval.tv_sec = packet->tp_sec;
			tmp_timeval.tv_usec = packet->tp_nsec / 1000;
			
			data = (u_char *) packet + packet->tp_mac;

			pkt->Init(props.link_type, &tmp_timeval, packet->tp_snaplen, packet->tp_len, data);

			if(packet->tp_snaplen == 0 || packet->tp_len == 0) {
				Error("empty packet header");
				return false;
			}
			return true;
			
			++stats.received;
			stats.bytes_received += packet->tp_len;
		}
		
		
		}
		return false;
	
	}

void TestimonySource::DoneWithPacket()
	{
	}

bool TestimonySource::PrecompileFilter(int index, const std::string& filter)
	{
	// Nothing to do. Packet filters are configured on
	// testimony daemon side
	return true;
	}

bool TestimonySource::SetFilter(int index)
	{
	return true;
	}

void TestimonySource::Statistics(Stats* s)
	{
	s->received = stats.received;
	s->bytes_received = stats.bytes_received;

	// TODO: get this information from the daemon
	s->link = stats.received;
	s->dropped = 0;
	}

ZEEK_IOSOURCE_NS::PktSrc* TestimonySource::Instantiate(const std::string& path, bool is_live)
	{
	return new TestimonySource(path, is_live);
	}

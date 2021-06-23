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
	
	temporary_queue_writer = new TemporaryQueueWriter();
	temporary_queue_writer->SetTestimonySource([this] () { this->AddPacketsToTemporaryQueue(); });
	temporary_queue_writer->SetStoppingProcess([this] () { this->running = false; } );
	temporary_queue_writer->StartThread();

	Opened(props);
	}


void TestimonySource::AddPacketsToTemporaryQueue()
	{
	while (running) 
		{
			
		const tpacket_block_desc *block = NULL;
		const tpacket3_hdr *packet;

		int res = testimony_get_block(td, 0, &block);
		if ( res == 0 && !block ) {
			if (!running) {
				return;
			}

			// Timeout
			continue;
		}

		if ( res < 0 )
			{
			Error("testimony_get_block:" + std::string(testimony_error(td)) + strerror(-res));
			running = false;
			Close();
			}

		int cnt = 0;

		testimony_iter_reset(td_iter, block);
		queue_access_mutex.lock();
		while ( (packet = testimony_iter_next(td_iter)) )
			{
			// Queue the packet
			char *data = new char[packet->tp_len + packet->tp_mac]; // 0 bytes alloc`d inside block of size 144 
			memcpy(data, packet, packet->tp_len + packet->tp_mac);
			
			temp_packets.emplace((tpacket3_hdr *) data);
			
			++stats.received;
			++cnt;
			stats.bytes_received += packet->tp_len;
			}
		queue_access_mutex.unlock();
		testimony_return_block(td, block);
		}
	Error("testimony loop stopped:");
	}

bool TestimonySource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! packets.empty() )
		{
		curr_packet = packets.front();
		packets.pop();

		curr_timeval.tv_sec = curr_packet->tp_sec;
		curr_timeval.tv_usec = curr_packet->tp_nsec / 1000;
		pkt->Init(props.link_type, &curr_timeval, curr_packet->tp_snaplen, curr_packet->tp_len, (const u_char *) curr_packet + curr_packet->tp_mac);

		return true;
		} 
	else 
		{
			queue_access_mutex.lock();
			if(!temp_packets.empty())
				{
				packets = std::move(temp_packets);
				queue_access_mutex.unlock();
				return ExtractNextPacket(pkt);
				}
			queue_access_mutex.unlock();
		}
		return false;
	}

void TestimonySource::DoneWithPacket()
	{
	if ( curr_packet )
		{
		delete curr_packet; 				//mismatched free/delate/delate[]
		curr_packet = NULL;
		}
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
	queue_access_mutex.lock();
	s->received = stats.received;
	s->bytes_received = stats.bytes_received;

	// TODO: get this information from the daemon
	s->link = stats.received;
	s->dropped = 0;
	queue_access_mutex.unlock();
	}

ZEEK_IOSOURCE_NS::PktSrc* TestimonySource::Instantiate(const std::string& path, bool is_live)
	{
	return new TestimonySource(path, is_live);
	}

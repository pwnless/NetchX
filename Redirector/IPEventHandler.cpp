#include "IPEventHandler.h"

extern DWORD icmping;

namespace
{
	constexpr size_t MaxPendingIcmpReplies = 1024;
	constexpr int MaxIPv4PacketBytes = 65535;

	struct DelayedIcmpReply
	{
		vector<char> packet;
		NF_IP_PACKET_OPTIONS options{};
		chrono::steady_clock::time_point due;
	};

	struct EarlierReplyFirst
	{
		bool operator()(const shared_ptr<DelayedIcmpReply>& left, const shared_ptr<DelayedIcmpReply>& right) const
		{
			return left->due > right->due;
		}
	};

	mutex icmpQueueLock;
	condition_variable icmpQueueReady;
	priority_queue<shared_ptr<DelayedIcmpReply>, vector<shared_ptr<DelayedIcmpReply>>, EarlierReplyFirst> icmpQueue;
	thread icmpWorker;
	atomic_bool icmpStopping = true;
	IPHandler::PacketPostCallback postSendForTesting = nullptr;
	IPHandler::PacketPostCallback postReceiveForTesting = nullptr;

	NF_STATUS PostSend(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options)
	{
		return postSendForTesting ? postSendForTesting(buffer, length, options) : nf_ipPostSend(buffer, length, options);
	}

	NF_STATUS PostReceive(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options)
	{
		return postReceiveForTesting ? postReceiveForTesting(buffer, length, options) : nf_ipPostReceive(buffer, length, options);
	}

	void PostFakeIcmpReply(const DelayedIcmpReply& reply);

	void IcmpWorker()
	{
		while (true)
		{
			shared_ptr<DelayedIcmpReply> reply;
			{
				unique_lock<mutex> lock(icmpQueueLock);
				while (!icmpStopping)
				{
					if (icmpQueue.empty())
					{
						icmpQueueReady.wait(lock, [] { return icmpStopping || !icmpQueue.empty(); });
						continue;
					}

					const auto due = icmpQueue.top()->due;
					if (chrono::steady_clock::now() < due)
					{
						// A new packet can have an earlier deadline than the one
						// currently at the top.  Wake and re-evaluate on every
						// enqueue instead of delaying it behind an older packet.
						icmpQueueReady.wait_until(lock, due);
						continue;
					}

					reply = move(icmpQueue.top());
					icmpQueue.pop();
					break;
				}
				if (icmpStopping)
					return;
			}

			if (!icmpStopping)
				PostFakeIcmpReply(*reply);
		}
	}
}
USHORT IPv4Checksum(PBYTE buffer, ULONG64 size)
{
	UINT32 sum = 0;
	ULONG64 i = 0;
	for (; i + 1 < size; i += 2)
	{
		sum += (buffer[i] << 8) + buffer[i + 1];
	}

	if (i < size)
		sum += buffer[i] << 8;

	while (sum > 0xffff)
	{
		sum = (sum >> 16) + (sum & 0xffff);
	}

	return ~sum & 0xffff;
}

USHORT ICMPChecksum(PBYTE buffer, ULONG64 size)
{
	UINT32 sum = 0;
	ULONG64 i = 0;
	for (; i + 1 < size; i += 2)
	{
		sum += buffer[i] + (buffer[i + 1] << 8);
	}

	if (i < size)
		sum += buffer[i];

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum & 0xffff;
}

namespace IPHandler
{
	bool INIT()
	{
		FREE();
		icmpStopping = false;
		try
		{
			icmpWorker = thread(IcmpWorker);
		}
		catch (...)
		{
			icmpStopping = true;
			return false;
		}
		return true;
	}

	void FREE()
	{
		icmpStopping = true;
		{
			lock_guard<mutex> lock(icmpQueueLock);
			while (!icmpQueue.empty())
				icmpQueue.pop();
		}
		icmpQueueReady.notify_all();
		if (icmpWorker.joinable())
			icmpWorker.join();
	}

	void SetPostCallbacksForTesting(PacketPostCallback postSend, PacketPostCallback postReceive)
	{
		postSendForTesting = postSend;
		postReceiveForTesting = postReceive;
	}
}

namespace
{
	void PostFakeIcmpReply(const DelayedIcmpReply& reply)
	{
		auto data = vector<BYTE>(reply.packet.begin(), reply.packet.end());

	{
		BYTE src[4];
		BYTE dst[4];
		memcpy(src, data.data() + 12, 4);
		memcpy(dst, data.data() + 16, 4);
		memcpy(data.data() + 12, dst, 4);
		memcpy(data.data() + 16, src, 4);
	}

	data[10] = 0x00;
	data[11] = 0x00;
	auto ipv4sum = IPv4Checksum(data.data(), reply.options.ipHeaderSize);
	data[10] = (ipv4sum >> 8);
	data[11] = ipv4sum & 0xff;

	data[reply.options.ipHeaderSize] = 0x00;
	data[reply.options.ipHeaderSize + 2] = 0x00;
	data[reply.options.ipHeaderSize + 3] = 0x00;
	auto icmpsum = ICMPChecksum(data.data() + reply.options.ipHeaderSize, static_cast<ULONG64>(data.size()) - reply.options.ipHeaderSize);
	data[reply.options.ipHeaderSize + 2] = icmpsum & 0xff;
	data[reply.options.ipHeaderSize + 3] = (icmpsum >> 8);

	#if defined(_DEBUG)
	printf("[Redirector][IPEventHandler][ipSend] Fake ICMP response for %d.%d.%d.%d\n", data[12], data[13], data[14], data[15]);
	#endif
	PostReceive((char*)data.data(), static_cast<int>(data.size()), (PNF_IP_PACKET_OPTIONS)&reply.options);
	}
}

void ipSend(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options)
{
	if (buffer == NULL || options == NULL)
		return;
	if (options->ip_family != AF_INET ||
		options->ipHeaderSize != 20 ||
		length < 28 ||
		length > MaxIPv4PacketBytes ||
		buffer[options->ipHeaderSize] != 0x08 ||
		icmpStopping)
	{
		PostSend(buffer, length, options);
		return;
	}

	shared_ptr<DelayedIcmpReply> reply;
	try
	{
		reply = make_shared<DelayedIcmpReply>();
		reply->packet.assign(buffer, buffer + length);
		reply->options = *options;
		reply->due = chrono::steady_clock::now() + chrono::milliseconds(icmping);
	}
	catch (...)
	{
		PostSend(buffer, length, options);
		return;
	}

	bool queued = false;
	{
		lock_guard<mutex> lock(icmpQueueLock);
		if (!icmpStopping && icmpQueue.size() < MaxPendingIcmpReplies)
		{
			icmpQueue.push(move(reply));
			queued = true;
		}
	}
	if (queued)
		icmpQueueReady.notify_one();
	else
		PostSend(buffer, length, options);
}

void ipReceive(const char* buffer, int length, PNF_IP_PACKET_OPTIONS options)
{
	PostReceive(buffer, length, options);
}

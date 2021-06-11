#pragma once
class UdpPlatformAddress
{
public:
	UdpPlatformAddress();
	UdpPlatformAddress(const UdpPlatformAddress& source);
	bool operator==(const UdpPlatformAddress& e) const;
	UdpPlatformAddress& operator=(const UdpPlatformAddress& e);
	char* GetAddress(char* buffer, int bufferLen) const;
	void SetAddress(const char* address);
	int GetHash();

protected:
	friend class UdpPlatformDriver;
	// note: platforms are required to be able to store their representation of the address in these 4 bytes
	// if we come across a platform that needs more space than this (or when we start doing IPv6), then we will
	// increase this space a bit.  This is sufficient for every platform so far and it avoids us having to
	// do an allocation, particularly since these things are passed around by-value a lot.
	unsigned char mData[4];
};
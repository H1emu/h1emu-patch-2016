#include "stdafx.h"
#include "UdpPlatformAddress.h"
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <Windows.h>
#include <assert.h>

UdpPlatformAddress::UdpPlatformAddress()
{
	memset(mData, 0, sizeof(mData));
}

UdpPlatformAddress::UdpPlatformAddress(const UdpPlatformAddress& source)
{
	memcpy(mData, source.mData, sizeof(mData));
}

UdpPlatformAddress& UdpPlatformAddress::operator=(const UdpPlatformAddress& e)
{
	memcpy(mData, e.mData, sizeof(mData));
	return(*this);
}

char* UdpPlatformAddress::GetAddress(char* buffer, int bufferLen) const
{
	if (buffer != nullptr) {
		if (bufferLen < 16)
		{
			*buffer = 0;
			return(buffer);
		}
		assert(buffer != nullptr);
		sprintf(buffer, "%d.%d.%d.%d", mData[0], mData[1], mData[2], mData[3]);
		return(buffer);
	}

	return nullptr;
}

void UdpPlatformAddress::SetAddress(const char* address)
{
	for (int i = 0; i < 4; i++)
	{
		mData[i] = (unsigned char)atoi(address);
		while (*address >= '0' && *address <= '9')
			address++;
		if (*address != 0)
			address++;
	}
}

bool UdpPlatformAddress::operator==(const UdpPlatformAddress& e) const
{
	return(memcmp(mData, e.mData, sizeof(mData)) == 0);
}


int UdpPlatformAddress::GetHash()
{
	return(*(int*)mData);
}
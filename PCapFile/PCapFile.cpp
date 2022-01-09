// PCapFile.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"

#include "PCapFile.h"

#include <iomanip>
#include <sstream>

/*** PCapFileError *****************************************************************/

std::string PCapFileError::createMessage(const char* msg, DWORD error)
{
	std::ostringstream os;
	os << msg << ": 0x" << std::hex << error;
	return os.str();
}

/*** PCapFile **********************************************************************/

PCapFile::~PCapFile()
{
	try {
		close();
	} catch (const PCapFileError&) {
	}
}

void PCapFile::create()
{
	// Create PCAP file
	fh = CreateFileW(fileName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (fh == INVALID_HANDLE_VALUE)
		throw PCapFileError("Cannot open file", GetLastError());
	// Write global header
	PCapHdr hdr{};
	hdr.magicNumber = magicMicroseconds;
	hdr.versionMajor = 2;
	hdr.versionMinor = 4;
	hdr.thiszone = 0; // UTC
	hdr.sigfigs = 0; // customary value
	hdr.snaplen = snaplen;
	hdr.network = LINKTYPE_RAW;
	DWORD wr;
	if (!WriteFile(fh, &hdr, sizeof(hdr), &wr, nullptr))
		throw PCapFileError("Cannot write global header", GetLastError());
	ready = true;
}

void PCapFile::close()
{
	if (fh != INVALID_HANDLE_VALUE && !CloseHandle(fh))
		throw PCapFileError("Cannot close file", GetLastError());
}

void PCapFile::writePacket(const std::string_view data, std::chrono::system_clock::time_point timestamp)
{
	PCapRecHdr hdr{};
	using namespace std::chrono;
	using namespace std::chrono_literals;
	auto ts = duration_cast<microseconds>(timestamp.time_since_epoch());
	hdr.tsSec = uint32_t(ts / 1s);
	hdr.tsUsec = uint32_t((ts % 1s).count());
	hdr.origLen = uint32_t(data.size());
	hdr.inclLen = std::min(hdr.origLen, snaplen);
	DWORD wr;
	if (!WriteFile(fh, &hdr, sizeof(hdr), &wr, nullptr))
		throw PCapFileError("Cannot write record header", GetLastError());
	if (!WriteFile(fh, data.data(), hdr.inclLen, &wr, nullptr))
		throw PCapFileError("Cannot write packet data", GetLastError());
}

void PCapFile::writePacket(const std::string_view data)
{
	return writePacket(data, std::chrono::system_clock::now());
}
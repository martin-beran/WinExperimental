// PCapFile.cpp : Defines the functions for the static library.
//

#include "PCapFile.h"

#include "pch.h"
#include "framework.h"

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
	fh = CreateFileW(fileName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (fh == INVALID_HANDLE_VALUE)
		throw PCapFileError("Cannot open file", GetLastError());
	PCapHdr hdr;
}

void PCapFile::close()
{
	if (fh != INVALID_HANDLE_VALUE && !CloseHandle(fh))
		throw PCapFileError("Cannot close file", GetLastError());
}

void PCapFile::writePacket(const std::string_view data, std::optional <std::chrono::system_clock::time_point>)
{
}

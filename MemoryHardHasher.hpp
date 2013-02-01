#pragma once
#pragma once
#if !defined MEMORYHARDHASHER_HPP_
#define MEMORYHARDHASHER_HPP_

// for cryptoAPI
#if defined _MSC_VER
#	pragma comment(lib, "crypt32.lib")
#endif


#include <memory>
#include <functional>
#include <string>
#include <sstream>
#include <iomanip>
//#include <tchar.h>
#include <Windows.h>
#include <wincrypt.h>
#include "AutoValue.hpp"

namespace Jvs { namespace Security
{

namespace SizeUnits
{
class KBType { };
static const KBType KB = KBType();
class MBType { };
static const MBType MB = MBType();
class GBType { };
static const GBType GB = GBType();
class TBType { };
static const TBType TB = TBType();

}

class MemoryHardHasher
{
private:
	unsigned long arraySize_;
	unsigned int jumpCount_;
	std::shared_ptr<unsigned char> array_;
	Jvs::AutoValue<HCRYPTPROV> cryptoHandle_;
	Jvs::AutoValue<HCRYPTHASH> hash_;



public:

	MemoryHardHasher(void)
		: arraySize_(0UL),
		jumpCount_(0U),
		array_(),
		cryptoHandle_()
	{
		this->acquireCryptoApi();
	}

	virtual ~MemoryHardHasher(void)
	{
	}

	unsigned int JumpCount(void) const
	{
		return this->jumpCount_;
	}

	MemoryHardHasher& JumpCount(unsigned int jumps)
	{
		this->jumpCount_ = jumps;
		return *this;
	}

	unsigned long ArraySize(void) const
	{
		return this->arraySize_;
	}

	MemoryHardHasher& ArraySize(unsigned long size)
	{
		this->arraySize_ = size;
		return *this;
	}

	MemoryHardHasher& ArraySize(unsigned long size, const SizeUnits::KBType&)
	{
		this->arraySize_ = size;
		this->arraySize_ *= 1024;
		return *this;
	}

	MemoryHardHasher& ArraySize(unsigned long size, const SizeUnits::MBType&)
	{
		this->arraySize_ = size;
		this->arraySize_ *= 1024 * 1024;
		return *this;
	}

	MemoryHardHasher& ArraySize(unsigned long size, const SizeUnits::GBType&)
	{
		this->arraySize_ = size;
		this->arraySize_ *= 1024 * 1024 * 1024;
		return *this;
	}

	template <typename GenerationProgress>
	std::string Hash(const std::string& source, const GenerationProgress& progressCallback)
	{
		unsigned long hashSize = 0UL;
		unsigned long location = 0UL;
		std::shared_ptr<unsigned char> sourceBytes(new unsigned char[source.size()], [](unsigned char* ptr) { delete [] ptr; });

		std::memcpy(sourceBytes.get(), &source[0], source.size());
		
		// set the initial hash
		std::shared_ptr<unsigned char> hashData;
		this->getHash(hashData, sourceBytes.get(), source.size(), hashSize);
		if (hashData == nullptr)
		{
			return "";
		}

		// allocate memory and fill with hashes
		this->array_.reset(new unsigned char[this->arraySize_], [](unsigned char* ptr) { delete [] ptr; });
		std::memcpy(this->array_.get() + location, hashData.get(), hashSize);
		location += hashSize;
		int percent = 0;
		int lastPercent = 0;
		while (location < this->arraySize_)
		{
			this->getHash(hashData, hashData.get(), hashSize, hashSize);
			if (hashData == nullptr)
			{
				this->array_.reset();
				return "";
			}

			std::memcpy((this->array_.get() + location), hashData.get(), hashSize);
			location += hashSize;
			percent = ((static_cast<double>(location) / this->arraySize_) * 100);
			if (lastPercent != percent)
			{
				lastPercent = percent;
				progressCallback(lastPercent, location);
			}
		}

		// jump through memory while hashing
		unsigned long* addr = reinterpret_cast<unsigned long*>(this->array_.get());
		unsigned long offset = *addr;
		if ((offset + sizeof(unsigned long)) / this->arraySize_ > 0)
		{
			offset = ((offset + sizeof(unsigned long)) % this->arraySize_);
		}
		
		addr = reinterpret_cast<unsigned long*>(this->array_.get() + offset);
		offset = *addr;
		this->getHash(hashData, reinterpret_cast<const unsigned char*>(addr), sizeof(unsigned long), hashSize);

		for (unsigned int jump = 0; jump < this->jumpCount_; ++jump)
		{
			if ((offset + sizeof(unsigned long)) / this->arraySize_ > 0)
			{
				offset = ((offset + sizeof(unsigned long)) % this->arraySize_);
			}
			
			addr = reinterpret_cast<unsigned long*>(this->array_.get() + offset);
			offset = *addr;
			this->getHash(hashData, hashData.get(), hashSize, hashSize);
		}

		// return the hash as a hex string
		std::stringstream hexhash;
		for (unsigned int i = 0; i < hashSize; ++i)
		{
			hexhash << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(*(hashData.get() + i));
		}
		
		return hexhash.str();
	}

private:
	void getHash(std::shared_ptr<unsigned char>& hashData, const unsigned char* source, unsigned long size, unsigned long & hashSize)
	{
		static DWORD dwordSize = sizeof(DWORD);

		this->hash_.Reset(0UL, CryptDestroyHash);

		if (!CryptCreateHash(this->cryptoHandle_, CALG_SHA_512, 0, 0, &this->hash_))
		{
			auto ret = ::GetLastError();
			std::stringstream s;
			s << std::hex << ret;
			OutputDebugStringA(s.str().c_str());
			this->hash_.Reset();
			return;
		}

		if (!CryptHashData(this->hash_, source, size, 0))
		{
			auto ret = ::GetLastError();
			std::stringstream s;
			s << std::hex << ret;
			OutputDebugStringA(s.str().c_str());
			return;
		}

		if (!CryptGetHashParam(this->hash_, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashSize), &dwordSize, 0))
		{
			auto ret = ::GetLastError();
			std::stringstream s;
			s << std::hex << ret;
			OutputDebugStringA(s.str().c_str());
			return;
		}

		hashData.reset(new unsigned char[hashSize], [](unsigned char* ptr) { delete [] ptr; });
		if (!CryptGetHashParam(this->hash_, HP_HASHVAL, hashData.get(), &hashSize, 0))
		{
			auto ret = ::GetLastError();
			std::stringstream s;
			s << std::hex << ret;
			OutputDebugStringA(s.str().c_str());
			return;
		}

	}

	void acquireCryptoApi(void)
	{
		this->cryptoHandle_.Reset(0UL, [](const HCRYPTPROV& val)
		{
			CryptReleaseContext(val, 0);
		});
		
		if (!CryptAcquireContext(&this->cryptoHandle_, nullptr, nullptr, PROV_RSA_AES, 0))
		{
			auto ret = ::GetLastError();
			std::stringstream s;
			s << std::hex << ret;
			OutputDebugStringA(s.str().c_str());
			this->cryptoHandle_.Reset();
			return;
		}

	}
};


}}

#endif
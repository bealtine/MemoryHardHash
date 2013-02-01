#pragma once
#if !defined AUTOVALUE_HPP_
#define AUTOVALUE_HPP_

namespace Jvs
{

template <typename T>
class AutoValue
{
private:
	template <typename U>
	struct Value
	{
		virtual void Destroy(void) = 0;
		virtual operator U&(void) = 0;
		virtual U* Get(void) = 0;
		virtual ~Value(void)
		{
		}
	};

	template <typename TU, typename Deleter>
	struct ValueImpl : public Value<TU>
	{
		TU v_;
		Deleter d_;

		ValueImpl(const TU& v, Deleter d)
			: v_(v),
			d_(d)
		{
		}

		virtual void Destroy(void)
		{
			this->d_(this->v_);
		}

		virtual operator TU&(void)
		{
			return this->v_;
		}

		virtual TU* Get(void)
		{
			return &this->v_;
		}
	};

	template <typename TU>
	struct DefaultDeleter
	{
		void operator()(const TU& src) const
		{
		}
	};

	Value<T>* value_;

	// non-assignable
	AutoValue<T>& operator=(const AutoValue<T>& src)
	{
		//if (this != &src)
		//{
		//	this->value_ = src.value_;
		//}

		//return *this;
	}

	// non-copyable
	AutoValue<T>(const AutoValue<T>& src)
	{
	}

public:

	AutoValue<T>(void)
		: value_(nullptr)
	{
	}

	template <typename U, typename TDeleter>
	AutoValue<T>(const U& value, TDeleter deleter)
		: value_(new ValueImpl<U, TDeleter>(value, deleter))
	{
	}

	template <typename U>
	explicit AutoValue<T>(const U& value)
		: value_(new ValueImpl<U, DefaultDeleter<U> >(value, DefaultDeleter<U>()))
	{
	}

	virtual ~AutoValue<T>(void)
	{
		if (this->value_)
		{
			this->value_->Destroy();
		}

		delete this->value_;
	}
	
	void Reset(void)
	{
		if (this->value_)
		{
			this->value_->Destroy();
		}

		delete this->value_;
	}

	template <typename U, typename TDeleter>
	void Reset(const U& value, TDeleter deleter)
	{
		this->Reset();
		this->value_ = new ValueImpl<U, TDeleter>(value, deleter);
	}

	template <typename U>
	void Reset(const U& value)
	{
		this->Reset(value, DefaultDeleter<U>());
	}

	operator T&(void)
	{
		return *this->value_;
	}

	T& operator->(void) { return *this->value_; }
    T* operator&(void) { return this->value_->Get(); }
};

}

#endif
#pragma once
#include <iostream>
#include <string>
#include <locale>
#include <algorithm>
#include <functional>

namespace Jyu {
	using QWORD = unsigned __int64;
	using DWORD = unsigned long;
	using WORD = unsigned short;
	using BYTE = unsigned char;

	template<typename T>
	struct non_negative
	{
		static bool call(T handle) noexcept
		{
			return (long long)(handle) > 0;
		}
	};

	template<typename Fun> struct _RAII {
		Fun _fun;
		_RAII(_RAII&&) = default;
		_RAII(const _RAII&) = default;
		template<typename FunArg> _RAII(FunArg&& fun) : _fun(std::forward<Fun>(fun)) {}
		~_RAII() { _fun(); }
	};
	typedef _RAII<std::function<void(void)>> finally;
	template<typename Fun> _RAII<Fun> RAII(const Fun& fun) { return _RAII<Fun>(fun); }
	template<typename Fun> _RAII<Fun> RAII(Fun&& fun) { return _RAII<Fun>(std::move(fun)); }
}
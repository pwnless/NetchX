#include "Based.h"

extern DWORD icmping;

extern "C" BOOL __cdecl aio_dial(int name, LPWSTR value);

namespace
{
	bool SetIcmpDelay(const wchar_t* value)
	{
		return aio_dial(AIO_ICMPING, const_cast<LPWSTR>(value)) == TRUE;
	}
}

int main()
{
	bool passed = SetIcmpDelay(L"0") && icmping == 0 &&
		SetIcmpDelay(L"60000") && icmping == 60000;

	const wchar_t* invalidValues[] = {
		L"",
		L"-0",
		L"-1",
		L"+1",
		L" 1",
		L"1ms",
		L"60001",
		L"999999999999999999999999"
	};
	for (const auto value : invalidValues)
		passed = passed && !SetIcmpDelay(value);

	passed = passed && aio_dial(AIO_ICMPING, NULL) == FALSE;
	printf("ICMP delay configuration regression: %s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}

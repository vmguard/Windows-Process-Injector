#undef UNICODE
#undef _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>

#pragma comment(lib, "psapi.lib")

class FixedInjector {
	bool isAdmin;


	// check admin 
	bool CheckAdminPrivileges() {
		BOOL isElevated = FALSE;
		HANDLE hToken = NULL;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			TOKEN_ELEVATION elevation;
			DWORD size = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
				isElevated = elevation.TokenIsElevated;
			}
			CloseHandle(hToken);
		}
		isAdmin = (isElevated == TRUE);
		return isAdmin;
	}

public:
	FixedInjector() {
		isAdmin = CheckAdminPrivileges();
	}
	// Performs classic loadlibrary remote thread injection
	// 1. Opens target process
	// 2. Allocates mem for DLL path
	// 3. write DLL path into process
	// 4. Finds LoadLibraryA address
	// 5. Create remote thread to execute loadlibrary
	bool InjectDLL(DWORD pid, const std::string& dllPath) {
		std::cout << "[+] Attempting to inject DLL into PID: " << pid << std::endl;


		char currentDir[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, currentDir);


		// validates dll path
		DWORD fileAttrib = GetFileAttributesA(dllPath.c_str());
		if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
			std::cout << "[!] Error: DLL not found at: " << currentDir << std::endl;
			std::cout << "Current working directory: " << currentDir << std::endl;
			return false;
		}

		std::cout << "[+] Opening process " << pid << std::endl;

		// Open target process with privs
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProcess) {
			DWORD error = GetLastError();
			std::cout << "Failed to open process. Error code: " << error << std::endl;

			if (error == ERROR_ACCESS_DENIED) {
				std::cout << "Access Denied. Running as admin could fix this issue" << std::endl;
			}
			return false;
		}

		std::cout << "[+] Process opened successfully. Handle " << hProcess << std::endl;

		try {
			
			std::cout << "[+] Allocating mem in target process" << std::endl;

			// Make sure DLLpath is null terminated
			std::string dllPathWithNull = dllPath + '\0';
			SIZE_T pathSize = dllPathWithNull.size();
			// allocates memory in the target process
			LPVOID allocatedMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (!allocatedMemory) {
				DWORD error = GetLastError();
				std::cout << "[!]Failed to allocate memory. Error code: " << error << std::endl;
				CloseHandle(hProcess);
				return false;
			}

			std::cout << "[+] Memory allocated at: 0x" << std::hex << allocatedMemory << std::dec << std::endl;

			// write dll path to allocated mem
			std::cout << "[+] Writing DLL to target process memory" << std::endl;


			SIZE_T bytesWritten = 0;
			BOOL writeResult = WriteProcessMemory(hProcess, allocatedMemory, dllPathWithNull.c_str(), pathSize, &bytesWritten);


			if (!writeResult) {
				DWORD error = GetLastError();
				std::cout << "[!] Failed to write memory. Error code: " << error << std::endl;
				VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
				CloseHandle(hProcess);
				return false;
			}

			HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
			if (!hKernel32) {
				DWORD error = GetLastError();
				std::cout << "[!] Failed to get kernel32 handle. Error code: " << error << std::endl;
				VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
				CloseHandle(hProcess);
				return false;
			}
			std::cout << "[+] kernel32.dll handle 0x" << std::hex << hKernel32 << std::dec << std::endl;

			FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
			if (!loadLibraryAddr) {
				DWORD error = GetLastError();
				std::cout << "[!] Failed to get LoadLibraryA address. Error Code: " << error << std::endl;

				VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
				return false;
			}

			std::cout << "[+] LoadLibraryA address: 0x" << std::hex << loadLibraryAddr << std::dec << std::endl;

			// Create remote thread in target process
			std::cout << "[+] Creating remote thread" << std::endl;

			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);

			if (!hThread) {
				DWORD error = GetLastError();
				std::cout << "[!] Failed to create remote thread. Error" << std::endl;
				VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
				CloseHandle(hProcess);
				return false;
			}

			std::cout << "[+] Remote thread created. Thread handle: " << hThread << std::endl;

			// wait for the thread to finish
			std::cout << "[+] waiting for thread to complete" << std::endl;

			DWORD waitResult = WaitForSingleObject(hThread, 5000);

			if (waitResult == WAIT_FAILED) {
				DWORD error = GetLastError();
				std::cout << "[!] Wait failed. Error code: " << error << std::endl;
			}
			else if (waitResult == WAIT_TIMEOUT) {
				std::cout << "[!] Warning: Thread timeout, dll might still load" << std::endl;
			}
			else {
				std::cout << "[+] Thread completed successfully" << std::endl;
			}

			// Get thread exit code
			DWORD exitCode = 0;
			if (GetExitCodeThread(hThread, &exitCode)) {
				if (exitCode == 0) {
					std::cout << "[!] Warning: Thread exit code 0, dll load might have failed" << std::endl;
				}
				else {
					std::cout << "[+] dll loaded at base address: 0x" << std::hex << exitCode << std::dec << std::endl;
				}
			}

			CloseHandle(hThread);
			VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
			CloseHandle(hProcess);

			std::cout << "[+] Injection successful!" << std::endl;
			return true;

		}
		catch (const std::exception& e) {
			std::cout << "[!] Unexpected error" << e.what() << std::endl;
			CloseHandle(hProcess);
			return false;
		}
	}
	// Get process ID
	DWORD GetProcessID(const std::string& processName) {
		DWORD pid = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);

			if (Process32First(hSnapshot, &pe32)) {
				do {
					std::string currentProcess = pe32.szExeFile;
					std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), ::tolower);

					std::string targetProcess = processName;
					std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), ::tolower);

					if (currentProcess.find(targetProcess) != std::string::npos) {
						pid = pe32.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnapshot, &pe32));
			}

			CloseHandle(hSnapshot);
		}


		return pid;
	}

	// list all running processes
	void ListProcesses() {
		std::cout << "\nRunning processes:" << std::endl;
		std::cout << std::string(80, '-') << std::endl;
		std::cout << std::left << std::setw(8) << "PID" << " | " << std::setw(20) << "Name" << " | " << std::setw(50) << "Executable" << std::endl;
		std::cout << std::string(80, '-') << std::endl;

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);

			if (Process32First(hSnapshot, &pe32)) {
				do {
					std::cout << std::left << std::setw(8) << pe32.th32ProcessID << " | " << std::setw(20) << pe32.szExeFile << " | ";

					// try to get full exe path
					HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

					if (hProcess) {
						char exePath[MAX_PATH];
						if (GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) {
							std::cout << std::setw(50) << exePath;
						}
						else {
							std::cout << std::setw(50) << "N/A";
						}
						CloseHandle(hProcess);
					}
					else {
						std::cout << std::setw(50) << "N/A";
					}

					std::cout << std::endl;
				} while (Process32Next(hSnapshot, &pe32));
			}


			CloseHandle(hSnapshot);
		}
	}


	// monitor for process and inject
	void WaitAndInject(const std::string& targetExe, const std::string& dllPath, float checkInterval = 1.0f) {
		std::cout << "Waiting for " << targetExe << " to start" << std::endl;
		std::cout << "Press Ctrl+C to stop monitoring\n " << std::endl;

		std::set<DWORD> injectedPIDs;
		std::string targetExeLower = targetExe;
		std::transform(targetExeLower.begin(), targetExeLower.end(), targetExeLower.begin(), ::tolower);

		while (true) {
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (hSnapshot != INVALID_HANDLE_VALUE) {
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(PROCESSENTRY32);

				if (Process32First(hSnapshot, &pe32)) {
					do {
						std::string procName = pe32.szExeFile;
						std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
						DWORD procPID = pe32.th32ProcessID;

						// check that it is the target process, and not already injected
						if (procName == targetExeLower && injectedPIDs.find(procPID) == injectedPIDs.end()) {
							std::cout << "\n" << std::string(50, '=') << std::endl;
							std::cout << "Found " << targetExe << " with PID: " << procPID << std::endl;
							std::cout << std::string(50, '=') << std::endl;

							//wait for process initialization
							std::cout << "Waiting for process initialization" << std::endl;
							std::this_thread::sleep_for(std::chrono::seconds(2));

							//attempt injection
							if (InjectDLL(procPID, dllPath)) {
								injectedPIDs.insert(procPID);
								std::cout << "\n Successfully injected into " << targetExe << " (PID: " << procPID << ")" << std::endl;
							}
							else {
								std::cout << "\n Failed to inject into " << targetExe << std::endl;
							}

							std::cout << "\nContinuing to monitor for new instances" << std::endl;
						}
					} while (Process32Next(hSnapshot, &pe32));
				}

				CloseHandle(hSnapshot);
			}

			// Remove dead processes from tracking
			std::set<DWORD> deadPIDs;
			for (DWORD pid : injectedPIDs) {
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
				if (!hProcess) {
					deadPIDs.insert(pid);
				}
				else {
					CloseHandle(hProcess);
				}
			}

			for (DWORD pid : deadPIDs) {
				injectedPIDs.erase(pid);
				std::cout << "Removing dead PID from tracking: " << pid << std::endl;
			}

			// Sleep before next check
			std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(checkInterval * 1000)));
		}
	}

	bool IsAdmin() const {
		return isAdmin;
	}

	void Run() {
		std::cout << std::string(60, '=') << std::endl;
		std::cout << "Remote Thread Injector" << std::endl;
		std::cout << std::string(60, '=') << std::endl;
		std::cout << std::endl;

		std::cout << "Running as Admin: " << (isAdmin ? "Yes" : "No") << std::endl;
		if (!isAdmin) {
			std::cout << "\nWarning: Injection may fail without admin privileges." << std::endl;
			std::cout << "Some processes require admin rights to inject into." << std::endl;

			std::cout << "\nContinue anyway? (y/n): ";
			char response;
			std::cin >> response;
			std::cin.ignore();

			if (response != 'y' && response != 'Y') {
				return;
			}
		}

		// config
		std::string defaultTarget = "notepad.exe";
		std::string defaultDLL = "C:\\DrawBox.dll";

		// Continuously monitor process list and inject into new instances
		while (true) {
			std::cout << "\nOptions:" << std::endl;
			std::cout << "1. Wait for specific program and inject on startup" << std::endl;
			std::cout << "2. List all running processes" << std::endl;
			std::cout << "3. Manual injection by PID" << std::endl;
			std::cout << "4. Test injection (using notepad.exe)" << std::endl;
			std::cout << "5. Exit" << std::endl;
			std::cout << std::endl;

			std::cout << "Select option: ";
			std::string choice;
			std::getline(std::cin, choice);

			if (choice == "1") {
				std::string targetExe;
				std::cout << "Target executable [" << defaultTarget << "]: ";
				std::getline(std::cin, targetExe);
				if (targetExe.empty()) {
					targetExe = defaultTarget;
				}
				std::string dllPath;
				std::cout << "Target DLL [" << defaultDLL << "]: ";
				std::getline(std::cin, dllPath);
				if (dllPath.empty()) {
					dllPath = defaultDLL;
				}

				// verify DLL exists
				DWORD fileAttrib = GetFileAttributesA(dllPath.c_str());
				if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
					std::cout << "\nERROR: DLL not found at: " << dllPath << std::endl;

					char currentDir[MAX_PATH];
					GetCurrentDirectoryA(MAX_PATH, currentDir);
					std::cout << "Current directory: " << currentDir << std::endl;
					std::cout << "Please specifiy the full path to the DLL." << std::endl;
					continue;
				}

				std::cout << "\nStarting monitor for: " << targetExe << std::endl;
				std::cout << "Using DLL: " << dllPath << std::endl;

				try {
					WaitAndInject(targetExe, dllPath);
				}
				catch (...) {
					std::cout << "Monitoring stopped." << std::endl;
				}


			}
			else if (choice == "2") {
				ListProcesses();
			}
			else if (choice == "3") {
				std::string pidStr;
				std::cout << "Enter PID: ";
				std::getline(std::cin, pidStr);

				try {
					DWORD pid = std::stoul(pidStr);

					std::string dllPath;
					std::cout << "DLL path [" << defaultDLL << "]: ";
					std::getline(std::cin, dllPath);
					if (dllPath.empty()) {
						dllPath = defaultDLL;
					}
					DWORD fileAttrib = GetFileAttributesA(dllPath.c_str());
					if (fileAttrib != INVALID_FILE_ATTRIBUTES) {
						InjectDLL(pid, dllPath);
					}
					else {
						std::cout << "DLL not found: " << dllPath << std::endl;
					}
				}
				catch (const std::exception& e) {
					std::cout << "Invalid input: " << e.what() << std::endl;
				}
			}
			else if (choice == "4") {
				std::cout << "\nTest mode using notepad.exe" << std::endl;
				std::cout << "Make sure notepad.exe is running" << std::endl;

				DWORD pid = GetProcessID("notepad.exe");
				if (pid != 0) {
					std::cout << "Found notepad.exe with PID: " << pid << std::endl;

					std::string dllPath;
					std::cout << "DLL path [" << defaultDLL << "]: ";
					std::getline(std::cin, dllPath);
					if (dllPath.empty()) {
						dllPath = defaultDLL;
					}

					DWORD fileAttrib = GetFileAttributesA(dllPath.c_str());
					if (fileAttrib != INVALID_FILE_ATTRIBUTES) {
						std::cout << "\nAttempting injection into notepad.exe (PID: " << pid << ")" << std::endl;
						InjectDLL(pid, dllPath);
					}
					else {
						std::cout << "DLL not found: " << dllPath << std::endl;
					}
				}
				else {
					std::cout << "notepad.exe not found. Open notepad first." << std::endl;
				}
			}
			else if (choice == "5") {
				std::cout << "Exiting" << std::endl;
				break;
			}
			else {
				std::cout << "Invalid choice" << std::endl;
			}

		}
	}

};

int main() {
	FixedInjector injector;
	injector.Run();

	std::cout << "\nPress Enter to exit";
	std::cin.ignore();
	return 0;
}
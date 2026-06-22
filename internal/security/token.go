package security

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	token    uint32
	hMapFile uintptr
)

const (
	fileMapRead       = 0x0004
	pageReadOnly      = 0x02
	fileMapReadAccess = 0x0004
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileMappingA = kernel32.NewProc("OpenFileMappingA")
	procMapViewOfFile    = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile  = kernel32.NewProc("UnmapViewOfFile")
	procCloseHandle      = kernel32.NewProc("CloseHandle")
)

// InitToken reads the 32-bit token from Windows Named Shared Memory
// "Local\BrayNBToken". Retries up to 20 times (500ms each = 10s).
// Returns 0 on success, error on failure.
func InitToken() error {
	name, _ := syscall.BytePtrFromString("Local\\BrayNBToken")

	const maxRetry = 20
	for i := 0; i < maxRetry; i++ {
		hMap, _, _ := procOpenFileMappingA.Call(
			uintptr(fileMapRead),
			0,
			uintptr(unsafe.Pointer(name)),
		)
		if hMap != 0 {
			pView, _, _ := procMapViewOfFile.Call(
				hMap,
				uintptr(fileMapReadAccess),
				0, 0,
				unsafe.Sizeof(uint32(0)),
			)
			if pView != 0 {
				token = *(*uint32)(unsafe.Pointer(pView))
				procUnmapViewOfFile.Call(pView)
				procCloseHandle.Call(hMap)
				hMapFile = 0
				return nil
			}
			procCloseHandle.Call(hMap)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("cannot read token after 10s")
}

// GetToken returns the cached token value.
// Returns 0 if InitToken was never called or failed.
func GetToken() uint32 {
	return token
}

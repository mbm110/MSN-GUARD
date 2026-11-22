//go:build ios && cgo

package memmon

/*
#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/task_info.h>

typedef size_t (*avail_fn)(void);

static avail_fn available_memory_fn;
static pthread_once_t available_memory_once = PTHREAD_ONCE_INIT;

static void resolve_available_memory(void) {
	available_memory_fn = (avail_fn)dlsym(RTLD_DEFAULT, "os_proc_available_memory");
}

// iOS 13+ exposes os_proc_available_memory. Resolve it lazily so older
// deployment targets can run without a link-time dependency.
static int read_available_memory(uint64_t *out) {
	pthread_once(&available_memory_once, resolve_available_memory);
	if (available_memory_fn == NULL) {
		return 0;
	}

	*out = (uint64_t)available_memory_fn();
	return 1;
}

static int get_phys_footprint(uint64_t *out) {
	task_vm_info_data_t vm;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t kr = task_info(
		mach_task_self(),
		TASK_VM_INFO,
		(task_info_t)&vm,
		&count
	);
	if (kr != KERN_SUCCESS) {
		return 0;
	}

#ifdef TASK_VM_INFO_REV1_COUNT
	if (count < TASK_VM_INFO_REV1_COUNT) {
		return 0;
	}
#endif

	*out = (uint64_t)vm.phys_footprint;
	return 1;
}
*/
import "C"

// readNative reports the current process footprint and, when supported,
// the remaining jetsam headroom.
func readNative() (footprint, available uint64, availableSupported bool) {
	// A zero footprint would read as zero pressure, masking the real state, so a
	// failed (or impossible zero) reading falls back rather than reporting native.
	var footprintOut C.uint64_t
	if C.get_phys_footprint(&footprintOut) == 0 || footprintOut == 0 {
		return 0, 0, false
	}
	footprint = uint64(footprintOut)

	var availableOut C.uint64_t
	if C.read_available_memory(&availableOut) == 0 {
		return footprint, 0, false
	}

	return footprint, uint64(availableOut), true
}

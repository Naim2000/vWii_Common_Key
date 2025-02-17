#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ogc/machine/processor.h>
#include <ogc/ipc.h>

#include "video.h"
#include "pad.h"
#include "realcode_bin.h"

#include "HCVA_tik.h"
#include "tik_certs.h"
#include "HCVA_tmd.h"
#include "tmd_certs.h"
#include "HCVA_0_enc_app.h"
#include "HCVA_1_enc_app.h"
#include "HCVA_2_enc_app.h"

#define HW_AHBPROT		0x0D800064
#define MEM2_PROT		0x0D8B420A

void __exception_setreload(unsigned seconds);

uint32_t keyhandles[3] = { 4, 11, 0 };

static inline bool validJumptablePtr(uint32_t x) {
	return (x >= 0xFFFF0040) && (x < 0xFFFFF000) && ((x & 3) == 0);
}

#define SRAMNOMIRR(x) (x - 0xF2B00000)
uint32_t* findTheSyscallTable(void) {
	uint32_t undfInstruction = read32(0xD4F0004);
	if ((undfInstruction & 0xFFFFF000) != 0xE59FF000 /* ? */)
		// SRNPROT is probably on
		return 0;

	uint32_t undfHandler = read32(0xD4F0004 + 8 /* pc is 2 steps ahead */ + (undfInstruction & 0xFFF));
	if (!validJumptablePtr(undfHandler))
		// Eh?
		return 0;

	undfHandler = SRAMNOMIRR(undfHandler);

	// arbitrary number. don't plan to go far
	for (int i = 0; i < 0x80; i += 4) {
		undfInstruction = read32(undfHandler + i);
		if ((undfInstruction & 0xFFFF0000) == 0xE59F0000) { // find the first thing loaded relative to PC
			uint32_t addr = undfHandler + i + 8 + (undfInstruction & 0xFFF);
			if (read32(addr) == 0xE6000010) {
				uint32_t syscallStackArgsTable = read32(addr + 4);
				uint32_t syscallTable = read32(addr + 8);

				if (validJumptablePtr(syscallStackArgsTable) && validJumptablePtr(syscallTable) && (syscallStackArgsTable - syscallTable) <= 0x400)
					return (uint32_t *)SRAMNOMIRR(syscallTable);
			}
		}
	}

	return 0;
}

void *patch_simple(void *start, void *end, const void *pattern, size_t pattern_len, const void *patch, size_t patch_len) {
	void *ret = NULL;
	void *ptr = NULL;

	while (ptr < end) {
		ptr = memmem(ptr, end - ptr, pattern, pattern_len);
		if (!ptr)
			break;

		memcpy(ptr, patch, patch_len);
		ret = ptr;
	}

	if (ret)
		DCFlushRange(start, end - (ret + patch_len));

	return ret;
}

int main(int argc, char **argv) {
	int ret;

	__exception_setreload(30);

	puts("Hello World!");

	// printf("HW_AHBPROT: %08X\n", read32(HW_AHBPROT));
	uint16_t* const IOSVersion = (uint16_t* const)0x80003140;
	printf("reloading IOS%u v%u (v%u.%u)....\n", IOSVersion[0], IOSVersion[1], IOSVersion[1] >> 8, IOSVersion[1] & 0xFF);
	IOS_ReloadIOS(*IOSVersion);
	// printf("HW_AHBPROT: %08X\n", read32(HW_AHBPROT));
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

	ret = IOS_Ioctlv(0x10001, 0, 1, 2, shasploit);
	if (ret < 0) {
		printf("/dev/sha exploit failed %i\n", ret);
		return ret;
	}

	int clock = 1000;
	while (!read32(HW_AHBPROT)) {
		usleep(1000);
		if (!clock--) {
			printf("clocked out (waiting on AHBPROT)\n");
			return -1;
		}
	}

	uint32_t* scTable = findTheSyscallTable();
	printf("syscall table => %p\n", scTable);
	if (!scTable)
		return -1;

	write16(MEM2_PROT, 0);

	void* mem2_ptr_cur = (void *)0x933E0000;
	void* mem2_ptr_end = (void *)0x94000000;

	/* ES common key index check */
	static const uint16_t pattern[] = {
		0x781B, // ldrb r3, [r3]
		0x2B01, // cmp r3, #0x1
		0xD901, // bls ...
	};

	/* IOSC_SetOwnership() PID mask */
	static const uint16_t pattern2[] = {
		0x2307, // mov r3, 0x7
		0x439d, // bic r5, r3
	};

	/* ES_Encrypt/Decrypt permissions check */
	static const uint16_t pattern3[]   = {
		0x2d06, // cmp r5, #SD_KEY
		0xd000, // beq ...
		0x4803, // ldr r0, =-1017
	};

	/* thank you damysteryman */
	static const uint16_t Kill_AntiSysTitleInstallv3_pt1_old[] = { 0x681A, 0x2A01, 0xD005 };	// Make sure that the pt1
	static const uint16_t Kill_AntiSysTitleInstallv3_pt1_patch[] = { 0x681A, 0x2A01, 0x46C0 };	// patch is applied twice. -dmm

	static const uint16_t Kill_AntiSysTitleInstallv3_pt2_old[] = { 0xD002, 0x3306, 0x429A, 0xD101 };	// Make sure that the pt2 patch
	static const uint16_t Kill_AntiSysTitleInstallv3_pt2_patch[] = { 0x46C0, 0x3306, 0x429A, 0xE001 };	// is also applied twice. -dmm

	static const uint16_t Kill_AntiSysTitleInstallv3_pt3_old[] = { 0x68FB, 0x2B00, 0xDB01 };
	static const uint16_t Kill_AntiSysTitleInstallv3_pt3_patch[] = { 0x68FB, 0x2B00, 0xDB10 };

	if (read16(0x0D8005A0) == 0xCAFE)
	{
		patch_simple(mem2_ptr_cur, mem2_ptr_end, Kill_AntiSysTitleInstallv3_pt1_old, sizeof(Kill_AntiSysTitleInstallv3_pt1_old), Kill_AntiSysTitleInstallv3_pt1_patch, sizeof(Kill_AntiSysTitleInstallv3_pt1_patch));
		patch_simple(mem2_ptr_cur, mem2_ptr_end, Kill_AntiSysTitleInstallv3_pt2_old, sizeof(Kill_AntiSysTitleInstallv3_pt2_old), Kill_AntiSysTitleInstallv3_pt2_patch, sizeof(Kill_AntiSysTitleInstallv3_pt2_patch));
		patch_simple(mem2_ptr_cur, mem2_ptr_end, Kill_AntiSysTitleInstallv3_pt3_old, sizeof(Kill_AntiSysTitleInstallv3_pt3_old), Kill_AntiSysTitleInstallv3_pt3_patch, sizeof(Kill_AntiSysTitleInstallv3_pt3_patch));
	}

	// void* ptr_IOSC_SetOwnership = MEM_PHYSICAL_TO_K0(read32((uint32_t)&scTable[0x71])); not worth it actually
	uint16_t* ptr = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, pattern2, sizeof(pattern2));
	if (ptr) {
		// printf("found pid mask code patch @ %p\n", ptr);
		ptr[0] = 0x2300;
		DCFlushRange(ptr, 4);
	}

	while (mem2_ptr_cur) {
		mem2_ptr_cur = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, pattern, sizeof(pattern));
		if (!mem2_ptr_cur)
			break;

		printf("found code patch @ %p\n", mem2_ptr_cur);
		uint16_t* pc = mem2_ptr_cur;
		pc[1] = 0x2B02;
		DCFlushRange(pc, 4);
		pc += 3;

		for (int i = 0; i < 0x20; i++) {
			if ((pc[i] & 0xFF00) == 0x4A00) { // ldr r2, [pc, #X]
				uint32_t* ptr_keyhandles = (uint32_t *)(((uint32_t)(pc + i + 2) & ~2) + ((pc[i] & 0x00FF) << 2));
				printf("ldr r2, =%#010x\n", *ptr_keyhandles);
				*ptr_keyhandles = MEM_VIRTUAL_TO_PHYSICAL(keyhandles);
				DCFlushRange(ptr_keyhandles, 4);
			}
		}

	}

	mem2_ptr_cur = (void *)0x933E0000; // again
	while (mem2_ptr_cur) {
		mem2_ptr_cur = memmem(mem2_ptr_cur, mem2_ptr_end - mem2_ptr_cur, pattern3, sizeof(pattern3));
		if (mem2_ptr_cur) {
			// printf("found keyslot permissions check @ %p\n", mem2_ptr_cur);
			*(uint16_t *)(mem2_ptr_cur + 2) = 0xE000;
			mem2_ptr_cur += 6;
			DCFlushRange(mem2_ptr_cur, 4);
		}
	}


	// OK!
	uintptr_t res_ptr = (uintptr_t)(realcode_bin + 4);
	write32(res_ptr + 8, MEM_VIRTUAL_TO_PHYSICAL(keyhandles));
	write32(res_ptr, 1);
	clock = 1000;
	while (read32(res_ptr) == 1) {
		usleep(1000);
		if (!clock--) {
			printf("clocked out (waiting on our code)\n");
			return -1;
		}
	}

	ret = read32(res_ptr);
	if (ret != 0) {
		printf("our code failed? %i\n", read32(res_ptr + 4));
		return ret;
	}

	DCInvalidateRange(keyhandles, 4 * 3);
	printf("keyhandles = [%08X %08X %08X]\n", keyhandles[0], keyhandles[1], keyhandles[2]);
	// printf("keydata    = %08X [%08X %08X %08X %08X]\n", read32(res_ptr + 8), keydata[0], keydata[1], keydata[2], keydata[3]);
	// keyhandles[2] = 11;

	u32 iv[4] = {};
	u32 data[4] __attribute__((aligned(0x20))) = {};
	u32 data_exp[4] = { 0x734654ce, 0x2098c90a, 0x0f0c2d28, 0x782269c7 };

	ret = ES_Encrypt(keyhandles[2], iv, data, sizeof(data), data);
	printf("ES_Encrypt => %i\n", ret);
	printf("[%08X %08X %08X %08X]\n", data[0], data[1], data[2], data[3]);
	printf("[%08X %08X %08X %08X] <= expected result\n", data_exp[0], data_exp[1], data_exp[2], data_exp[3]);


#if 0
	uint64_t titleID = 0x0001000248435641;
/*
	__attribute__((aligned(0x20))) static tikview view;
	while (!ES_GetTicketViews(titleID, &view, 1)) {
		ret = ES_DeleteTicket(&view);
		printf("ES_DeleteTicket(%016llx) ret=%i\n", view.ticketid, ret);
	}
*/
	puts("try import HCVA ticket...");
	ret = ES_AddTicket((signed_blob *)HCVA_tik, HCVA_tik_size, (signed_blob *)tik_certs, tik_certs_size, NULL, 0);
	printf("ES_AddTicket => %i\n", ret); // but wait!

	puts("try import HCVA title...");
	ret = ES_AddTitleStart((signed_blob *)HCVA_tmd, HCVA_tmd_size, (signed_blob *)tmd_certs, tmd_certs_size, NULL, 0);
	printf("ES_AddTitleStart => %i\n", ret);

	int i;
	for (i = 0; i < 3; i++) {
		const void *data[] = { HCVA_0_enc_app, HCVA_1_enc_app, HCVA_2_enc_app };
		unsigned size[] = { HCVA_0_enc_app_size, HCVA_1_enc_app_size, HCVA_2_enc_app_size };

		int cfd = ret = ES_AddContentStart(titleID, i);
		printf("ES_AddContentStart(%i) => %i\n", i, ret);
		if (ret < 0)
			break;

		ret = ES_AddContentData(cfd, data[i], size[i]);
		printf("ES_AddContentData(%i) => %i\n", i, ret);

		ret = ES_AddContentFinish(cfd);
		printf("ES_AddContentFinish(%i) => %i\n", i, ret);
		if (ret < 0)
			break;
	}

	ret = ES_AddTitleFinish();
	printf("ES_AddTitleFinish() => %i\n", ret);
#endif
	return ret;
}

__attribute__((destructor))
void finished() {
	initpads();
	puts("\nmain() exited with some code. idk what");
	puts("Press any button to exit.");
	// sleep(3);
	wait_button(0);
}

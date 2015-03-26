.extern hook_map

.text
.global trampoline

/*
struct saved_prolog {
	uint8_t saved_ops[4*10];
	uint32_t cont;
};

struct hook_data {
	uint32_t cpsr;
	uint32_t r0, r1, r2, r3;
	uint32_t *sp;
	uint32_t skip_lr;
};

struct hook_mapping {
	uint32_t lr;
	hook_handler handler;
	struct saved_prolog *prolog;
};
*/

/* r0 = &trampoline, lr = &target_func+x */
/* sp = {orig_r0, orig_r1, orig_r2, orig_r3, orig_r4, orig_lr, ...} */
trampoline:
/*
	push {lr}

	ldr r0, =mutex
	bl lock_mutex

	pop {lr}
*/
	mov r1, lr

	/* save content of CPSR as early as possible */
	mrs r2, APSR
	push {r2}

	/* get pointer to &hook_map[0] */
	ldr r0, =hook_map
	ldr r0, [r0]

loop:
	ldr r2, [r0]
	cmp r2, r1
	beq handle

	add r0, r0, $12 /* increase by sizeof(struct hook_mapping) */
	b loop

handle: /* r0 points to correct hook_map entry */

	/* sp = {cpsr, orig_r0, orig_r1, orig_r2, orig_r3, orig_r4, orig_lr} */
	add r1, sp, $28
	str r1, [sp, $20]

	/* sp = {cpsr, orig_r0, orig_r1, orig_r2, orig_r3, orig_sp, orig_lr} */
	push {r0}
	ldr r1, [r0, $4]

	add r0, sp, $4		/* sp = struct hook_data *data */
	blx r1

	pop {r1}		/* get pointer to hook_map entry */

	/* sp = {cpsr, orig_r0, orig_r1, orig_r2, orig_r3, orig_sp, orig_lr} */
	cmp r0, $0
	beq cont_func

skip_func:
	ldr lr, [sp, $24]	/* let r0 be the return address to caller */
	b fix_register

cont_func:
	ldr lr, [r1, $8] 	/* get pointer to saved prolog */

fix_register:
	/*
	 * lr = return address
	 * r1 = &hook_map[x]
	 */

	/* restore CPSR */
	pop {r0}
	msr APSR_nzcvqg, r0

	/* replace orig_sp with orig_lr and orig_lr with lr */
	ldr r0, [sp, $20]
	str r0, [sp, $16]
	str lr, [sp, $20]

	/*
	 * restore registers
	 * sp = {orig_r0, orig_r1, orig_r2, orig_r3, orig_lr, lr}
	 */
	pop {r0, r1, r2, r3, lr}

/*
	push {r0, r1}

	ldr r0, =mutex
	bl unlock_mutex

	pop {r0, r1}
*/

	/* sp = {lr} */
	pop {pc}		/* sp should now be returned to original */

lock_mutex:
	mov r1, $1
	ldrex r2, [r0]
	cmp r2, r1

	wfeeq
	beq lock_mutex

	strexne r2, r1, [r0]
	cmpne r2, $1
	beq lock_mutex

	/* lock aquired */
	dmb
	bx lr

unlock_mutex:
	mov r1, $0
	dmb
	str r1, [r0]

	dsb
	sev

	bx lr

.data
mutex:
	.byte 0x00, 0x00, 0x00, 0x00

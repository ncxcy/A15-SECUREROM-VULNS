# SecureROM t8110 (A15) Reverse eng list of vulns
**Target:** SecureROM for t8110si, iBoot-6338.0.0.200.19  
**Load base:** 0x100000000  
**File size:** 0x100000 bytes (1MB)  
**Device:** iPhone 14 (D27AP), CPID:8110, CPFM:03  

> [!IMPORTANT]
> Claude code was used for documenting markdown not for reverse engineering, and im posting this as RESEARCH, i hope this is helpfull for someone building their own tool for bypassing activation lock / building jailbreak tool from this and if you publish some kind of tools you must put my creds if you are used any of these vulnerabilities from here. now focusing on finding vulnerabilities (vulnerabilities are confirmed by coding PoC's (will be uploaded)).
 
---

## 1. Security Posture

| Feature | Status |
|---|---|
| PACIBSP / RETAB | Present on most functions |
| BRAAZ / BLRAA (indirect call auth) | All slot dispatch sites use BRAAZ - NO plain BLR for fn ptrs |
| PAC on slot fn ptrs | YES - every dispatch: AUTIBSP + BRAAZ X0/X1 |
| Plain BLR (exploitable) | 8 sites, all call sub_100028670 (stack probe helper - not useful) |
| Range check bypass flag | 0x1FC0218E6 bit 0 - bypasses all write range checks |
| CPFM:03 bypass flag state | **Always set on this device** - range check disabled entirely |

**Critical:** All 4 DFU slot dispatch functions (0x100014544, 0x10001457c, 0x1000145b4, 0x1000145ec) use `AUTIBSP + BRAAZ X0`. No unauthenticated dispatch path exists through the slot table

---

## 2. SRAM Layout - Complete Field Map
**Buffer base:** 0x1FC022000 (DFU download buffer, 0x800 bytes)

### Inside the DFU buffer (0x000 – 0x7FF) - key fields:

| Offset | Address | Field | Set by | Notes |
|---|---|---|---|---|
| 0x370 | 0x1FC022370 | USB queue node base | sub_10000AF98 | Linked-list base |
| 0x374 | 0x1FC022374 | Queue node +4 | sub_10000AF98 | STRH WZR (zeroed) |
| 0x510 | 0x1FC022510 | USB context ptr | sub_10000AF98 | STR X8 |
| 0x530 | 0x1FC022530 | USB state word | sub_10000AF98 | Read/written frequently |
| 0x534 | 0x1FC022534 | USB active flag | sub_10000AF98 | Read by sub_10000BB64 |
| 0x538 | 0x1FC022538 | USB counter | sub_10000B164 | Read/written |
| 0x540 | 0x1FC022540 | USB endpoint state | sub_10000B164 | LDRB checks |
| 0x548 | 0x1FC022548 | USB endpoint obj ptr | sub_10000AF98 | STR X0 |
| **0x570** | **0x1FC022570** | **DFU init flag** | **sub_10000C440** | **=1 > skip re-init. KEY EXPLOIT FIELD** |
| 0x578 | 0x1FC022578 | Handler selector | sub_10000C250 | 0=sub_100010F5C, 1=sub_100019C4C |
| 0x579 | 0x1FC022579 | Nonce byte | sub_10000C25C | Read as arg to handler |
| 0x57A | 0x1FC02257A | Nonce byte 2 | sub_10000C25C | STRB |
| 0x57B | 0x1FC02257B | Nonce init flag | sub_10000C25C | =1 after init |
| **0x580** | **0x1FC022580** | **Alloc base (DFU pool)** | **sub_10000C2B8** | **=0 > full re-init triggers. KEY EXPLOIT FIELD** |
| 0x588 | 0x1FC022588 | Main handler fn ptr | sub_10000C4B4 | Written after handler dispatch |
| 0x590 | 0x1FC022590 | Buffer ptr table base | sub_10000C2B8 | 5 entries, 8 bytes each |
| 0x598 | 0x1FC022598 | Buffer ptr [0] = da0 source | sub_10000C2B8 | alloc_base + 0 |
| 0x5A0 | 0x1FC0225A0 | Buffer ptr [1] | sub_10000C2B8 | alloc_base + 0x100 |
| 0x5B8 | 0x1FC0225B8 | USB descriptor ptr | sub_10000D670 | STR X1 |
| 0x5C0 | 0x1FC0225C0 | USB transfer count | sub_10000D74C | R/W |
| 0x5C8 | 0x1FC0225C8 | USB endpoint context | sub_10000D81C | Base of large struct |
| 0x5CC | 0x1FC0225CC | Transfer state word | sub_10000D81C | R/W frequently |
| 0x5D0 | 0x1FC0225D0 | Transfer context | sub_10000DC1C | ADD (base addr) |
| 0x5D4 | 0x1FC0225D4 | Transfer count 2 | sub_10000DD0C | R/W |
| 0x5D8 | 0x1FC0225D8 | Transfer queue ptr | sub_10000D81C | STR |
| 0x5E0 | 0x1FC0225E0 | Transfer queue base | sub_10000D81C | STR X10, many readers |
| 0x5E8 | 0x1FC0225E8 | Transfer item [0] | sub_10000D81C | STP |
| 0x5F0 | 0x1FC0225F0 | Transfer item [1] | sub_10000D81C | STP, 14 readers |
| 0x5F8 | 0x1FC0225F8 | Transfer descriptor ptr | sub_10000E150 | Many readers |
| 0x600 | 0x1FC022600 | Transfer descriptor base | sub_10000F434 | Many R/W |
| 0x760 | 0x1FC022760 | USB HW ctrl reg ptr | sub_100010348 | 23+ references |
| 0x778 | 0x1FC022778 | USB PHY context | sub_10001137C | 20+ references |
| 0x77A | 0x1FC02277A | PHY mode byte | sub_100010FD0 | LDRB/STRB |
| 0x77C | 0x1FC02277C | PHY register base | sub_100010F68 | 9+ references |
| 0x780 | 0x1FC022780 | PHY state struct | sub_100011180 | R/W |
| 0x784 | 0x1FC022784 | PHY counter | sub_100011180 | STR WZR |
| 0x788 | 0x1FC022788 | PHY data word | sub_100011E48 | STR W8 |
| 0x78C | 0x1FC02278C | PHY control word | sub_100011AB4 | STR |
| 0x790 | 0x1FC022790 | PHY base ptr | sub_100010F68 | STUR X0 |
| 0x7A0 | 0x1FC0227A0 | TX/RX base | sub_100010FD0 | Many references |
| 0x7A8 | 0x1FC0227A8 | TX buf ptr | sub_100010FD0 | LDR |
| 0x7B0 | 0x1FC0227B0 | RX base | sub_100010FD0 | 4 references |
| 0x7B8 | 0x1FC0227B8 | RX buf ptr | sub_10001137C | LDR |
| 0x7C0 | 0x1FC0227C0 | TX/RX size pair | sub_100010FD0 | STP |
| 0x7C8 | 0x1FC0227C8 | TX/RX size pair [1] | sub_100010FD0 | STP |
| 0x7E8 | 0x1FC0227E8 | USB req object base | sub_100011180 | ADD (base addr) |

### Gap (0x800 – 0xDAF) - USB DMA region

| Offset | Address | Field | Set by | Notes |
|---|---|---|---|---|
| **0x800** | **0x1FC022800** | **USB DMA descriptor** | **sub_100011AB4** | **0x4000000080 - hardware DMA ctrl word. NEVER zero.** |
| 0x81C | 0x1FC02281C | DMA active flag | sub_100011AB4 | STRB |
| 0x848 | 0x1FC022848 | RX buffer ptr | sub_100011AB4 | STR X8 (runtime ptr) |
| 0x850 | 0x1FC022850 | RX buffer size | sub_100011AB4 | STR W8 |
| 0x854 | 0x1FC022854 | DMA clear field | sub_100011AB4 | STR WZR |
| 0x858 | 0x1FC022858 | DMA ctrl word 2 | sub_100011AB4 | 0x4000000000 |
| 0x868 | 0x1FC022868 | DMA completion flag | sub_100011AB4 | STR WZR |
| 0x874 | 0x1FC022874 | DMA done flag | sub_100011AB4 | STRB |
| 0x8A0 | 0x1FC0228A0 | TX buffer ptr | sub_100011AB4 | STR X8 (runtime ptr) |
| 0x8A8 | 0x1FC0228A8 | TX buffer size | sub_100011AB4 | STR W8 |

### USB / DFU control block (0xCB0 – 0xDA8):

| Offset | Address | Field | Notes |
|---|---|---|---|
| 0xCB0 | 0x1FC022CB0 | USB interface mode | LDRB, 26+ refs |
| 0xCB1 | 0x1FC022CB1 | DFU mode flag | Set by DFU init |
| 0xCB2 | 0x1FC022CB2 | Interface state | STRB by handler |
| 0xCB3 | 0x1FC022CB3 | Interface state 2 | STRB by handler |
| 0xCB8 | 0x1FC022CB8 | USB device string ptr | sub_100012F70 |
| 0xCC0 | 0x1FC022CC0 | USB class request state | sub_100012D74 |
| 0xCC4 | 0x1FC022CC4 | wValue from SETUP | sub_100013470 |
| 0xCC8 | 0x1FC022CC8 | wLength from SETUP | sub_100013470 |
| 0xCCC | 0x1FC022CCC | Interface descriptor count | sub_1000130F4 checks this first |
| 0xCD0 | 0x1FC022CD0 | USB request dispatcher | sub_100013470 jump table |
| 0xCD8 | 0x1FC022CD8 | USB context obj ptr | sub_100013470 |
| 0xCE0 | 0x1FC022CE0 | USB state byte | sub_100012D74, sub_100012D98 |
| 0xCE1 | 0x1FC022CE1 | USB substate | sub_100013470 |
| 0xCE2 | 0x1FC022CE2 | wIndex from SETUP | sub_100013470 |
| 0xCE4 | 0x1FC022CE4 | bRequest byte | sub_100013470 |
| 0xCE6 | 0x1FC022CE6 | Interface index | sub_100012E0C |
| 0xCE8 | 0x1FC022CE8 | Request obj ptr | sub_100013EB0 |
| 0xCF0 | 0x1FC022CF0 | Request context | sub_100012F70 |
| 0xCF8 | 0x1FC022CF8 | Request data ptr | sub_100012EA4 |
| 0xD00 | 0x1FC022D00 | Descriptor buf ptr | sub_1000130F4 |
| 0xD08 | 0x1FC022D08 | Descriptor buf ptr 2 | sub_1000130F4 |
| **0xD80** | **0x1FC022D80** | **DFU state byte** | **sub_100013FD0 spins while ==0** |
| 0xD81 | 0x1FC022D81 | DFU endpoint init flag | sub_100014054 |
| 0xD82 | 0x1FC022D82 | DFU state machine | States: 2=idle, 5=dnload-idle, 7=manifest |
| **0xD84** | **0x1FC022D84** | **Transfer size limit** | **sub_100013FD0 sets; sub_1000142E4 checks** |
| 0xD88 | 0x1FC022D88 | Transfer offset | sub_100013FD0 returns this |
| 0xD8C | 0x1FC022D8C | bytes_received counter | Reset to 0 by ABORT |
| 0xD90 | 0x1FC022D90 | wLength storage (u32) | sub_100014130 |
| 0xD94 | 0x1FC022D94 | DFU transfer count | sub_100014054 |
| 0xD98 | 0x1FC022D98 | wLength storage (u16) | sub_100014054 |
| **0xDA0** | **0x1FC022DA0** | **memcpy dst ptr (da0)** | **THE TARGET - sub_100013FD0 resets this on every SETUP** |
| 0xDA8 | 0x1FC022DA8 | USB endpoint buf ptr | sub_100014054 |
| 0xDB0 | 0x1FC022DB0 | Linked-list node | FUN_10000BA58, self-referential |
| 0xDC8 | 0x1FC022DC8 | Interface count | sub_100014054 = 1 |
| 0xDD0 | 0x1FC022DD0 | Descriptor ptr | sub_100014054 > DAT_10002DAB0 |
| 0xDD8 | 0x1FC022DD8 | = 1 | sub_100014054 |
| 0xDE0 | 0x1FC022DE0 | Descriptor ptr 2 | sub_100014054 > DAT_10002DAB9 |
| 0xE08 | 0x1FC022E08 | ctrl handler fn ptr | sub_100014054 > FUN_10001412C |
| 0xE10 | 0x1FC022E10 | data callback fn ptr | sub_100014054 > FUN_1000142E4 |
| 0xE38 | 0x1FC022E38 | interface data ptr | sub_100014054 > DAT_1000143E0 |
| **0xE58** | **0x1FC022E58** | **Active slot ptr** | **All BRAAZ dispatches load from here** |
| 0xE60 | 0x1FC022E60 | Slot table start | 3 slots × 0x30 bytes, fn ptrs at +8/+10/+18/+20 |

---

## 3. Confirmed Vulnerabilities

### VULN-01 - DFU TOCTOU Race (Confirmed, fires iter 0 every run)
**Handler:** 0x10001412C (dfu_control_request_handler)  
**Race window:** Between DFU_DNLOAD SETUP (stores wLength at 0xD90/D98) and OUT data phase  
**Trigger:** DFU_ABORT resets bytes_received (0xD8C) to 0, leaves wLength stale  
**Effect:** USB hardware delivers OUT data; callback checks `bytes_received(0) + len ≤ limit` > passes > memcpy runs starting at da0+0, overflowing past buf_end  
**Reliability:** 100% - fires on iter 0, 2-3 aborts, every run

### VULN-02 - Memory Write Primitive via da0 Overflow
**Mechanism:** TOCTOU race causes memcpy to write attacker payload starting at da0+0, extending past 0x1FC022800 (buf_end) by 0x5A8 bytes  
**Range check:** sub_10000AB5C - **bypassed entirely on CPFM:03** (bypass flag at 0x1FC0218E6 bit 0 = 1)  
**Limitation:** sub_100013FD0 resets da0 on every DFU SETUP before data arrives

### VULN-03 - Re-init Skip via 0x570 / 0x580 flags
**Discovery:** IDA decomp of sub_10000C440 and sub_10000C4B4  
**Mechanism:**  
- `buf[0x570] = 1` > sub_10000C440 skips `dfu_endpoint_setup` (da0 not reset by re-init)
- `buf[0x580] = 1` > sub_10000C4B4 skips `sub_10000C2B8` (da0 not reset by event loop)  
**Effect:** da0 = rsa_pkcs1_verify survives across USB events and re-enumeration

### VULN-04 - rsa_pkcs1_verify Data-Write Patch
**Target:** sub_100024730 (rsa_pkcs1_verify)  
**Confirmed:** Calls sub_100024BBC (Montgomery exp) + sub_1000253C0 (PKCS1 pad check)  
**Patch:** Write `MOV W0,#0 + RET` (8 bytes: `00 00 80 D2 C0 03 5F D6`) to 0x100024730  
**Effect:** Every RSA signature check returns 0 (success) > ROM accepts any binary

### VULN-05 - Range Check Bypass Flag (CPFM:03)
**Address:** 0x1FC0218E6 bit 0  
**Confirmed:** sub_10000AB60 checks this first - if set, all range validation skipped  
**Status on device:** Always 1 (CPFM:03 = development fused)  
**Effect:** da0 can point to ROM (0x100024730) and memcpy will write there - no DRAM range restriction

---

## 4. Key Function Map

| Address | Name | Role |
|---|---|---|
| 0x10001412C | dfu_control_request_handler | SETUP/ABORT/CLRSTATUS handler - TOCTOU target |
| 0x1000142E4 | dfu_download_data_callback | memcpy into da0 - write primitive |
| 0x100014054 | dfu_endpoint_setup | Resets da0 - must be bypassed |
| 0x10000C4B4 | dfu_event_loop_tick | Checks 0x580, dispatches handler |
| 0x10000C440 | dfu_reinit | Checks 0x570, calls dfu_endpoint_setup |
| 0x10000C2B8 | dfu_pool_init | Checks 0x580, resets alloc pool and da0 |
| 0x10000C54C | dfu_teardown | Checks 0x570==1 > tears down interface |
| 0x10000AB5C | sram_range_validator | Bypass if 0x1FC0218E6 & 1 (always on CPFM:03) |
| 0x10000AA90 | sram_range_setter | Sets allowed write window |
| 0x100013FD0 | dfu_recv_setup | Sets da0, spins on 0xD80, calls teardown |
| 0x100024730 | rsa_pkcs1_verify | PATCH TARGET - write MOV W0,0 + RET here |
| 0x100024BBC | rsa_montgomery_exp | Inner RSA math |
| 0x1000253C0 | pkcs1_pad_check | PKCS#1 v1.5 padding verifier |
| 0x100025564 | rsa_montgomery_exp_entry | RSA exponentiation |
| 0x100024730 | rsa_pkcs1_verify | Returns 0=success, 0xFFFFFFFF=fail |
| 0x10001A68C | security_mode_decision | Reads CPFM fuses - bit 8 controls unsigned boot |
| 0x10000C440 | sub_10000C440 | Re-init guard - checks 0x570 |
| 0x10001412C | dfu_control_request_handler | wLength check: ≤ 0x800 accepted |
| 0x100007EE4 | boot_chain_start | Calls sub_10000C54C > begins iBSS load |
| 0x100030940 | rsa_pkcs1_verify ptr | Crypto vtable entry - in ROM data |
| 0x10002F5F0 | handler_stub | sub_100010F5C returns ptr here |
| 0x100019C4C | handler_main | Sets 0x1FC023870, returns handler ptr |

---

## 5. DFU Control Flow (Confirmed)

```
Power on > dfu_init (0x10000C440)
  > sub_100012A84 (USB device setup)
  > sub_100012F70 ("Apple Mobile Device (DFU Mode)")  
  > sub_100014054 (dfu_endpoint_setup)
       > sub_10000C6D4(1) > da0 = alloc_base
       > allocates 0x800-byte download buffer
       > registers control + data callbacks
  > sub_1000130F4 (USB descriptor setup)
  > MEMORY[0x1FC022570] = 1

Event loop: sub_10000C4B4 (called from sub_10001A63C)
  > if 0x580 == 0: sub_10000C2B8 (re-init pool) > resets da0
  > sub_10000C25C (nonce setup)
  > v0 = MEMORY[0x588] or sub_100010F5C/sub_100019C4C
  > v1 = v0(nonce)
  > sub_10000C440(v1):
       > if MEMORY[0x570] & 1 == 0: dfu_endpoint_setup > resets da0
       > else: SKIP (da0 preserved)

DNLOAD SETUP > sub_100014130:
  > wLength ≤ 0x800 accepted
  > sub_100013FD0(new_buf, 0x800, 0):
       > MEMORY[0xDA0] = new_buf  < RESETS da0
       > MEMORY[0xD84] = 0x800
       > spins while MEMORY[0xD80] == 0
       > sub_10000C54C > teardown if 0x570==1

DNLOAD DATA > sub_1000142E4:
  > sub_10000AB5C(da0 + bytes_received, len):
       > if 0x1FC0218E6 & 1: return 1 (bypass - always on CPFM:03)
  > memcpy(da0 + bytes_received, ep_buf, len)
  > bytes_received += len
```

---

## 6. Exploit Chain (Current State)

### What works:
- Race fires iter 0 every time (100% reliability)
- 0x570=1 + 0x580=1 flags suppress re-init
- 0xD80=1 prevents spin-wait crash
- da0 overflow to 0x100024730 is correct

### Current blocker:
`sub_100013FD0` at line `MEMORY[0xDA0] = new_buf` - called by the DNLOAD SETUP handler for stage 2 - **resets da0 before the data arrives**. Stage 2 DNLOAD SETUP triggers this, which means da0 is overwritten before our 8-byte patch goes through the callback.

### Possible fixes (to research):

**Fix A - Send stage 2 data WITHOUT a SETUP (inject raw OUT)**  
USB protocol normally requires SETUP before data. Possible with raw libusb async - submit an OUT transfer to endpoint 0 without sending SETUP first. If the USB controller has buffered data from the previous race, the callback fires with da0 still = rsa_verify.

**Fix B - Overflow wLength storage (0xD90) to skip sub_100013FD0**  
If 0xD90 (wLength) still matches the stage 2 transfer length, sub_100014130 may skip calling sub_100013FD0 entirely for certain state machine values. Needs state machine analysis.

**Fix C - Use CLRSTATUS zero-write to zero sub_100013FD0's `new_buf` store**  
DFU_CLRSTATUS computes `ptr = da0 + (bytes_received - 0x10)` and writes 16 zero bytes. If da0 = rsa_verify and bytes_received = 0x10, writes zeros at rsa_verify+0 - which IS `MOV X0,X0 + NOP` (not a return). Not directly useful but shows another write path.

**Fix D - Use DFU_MANIFEST state to trigger execution**  
After a complete DNLOAD sequence, ROM enters dfuMANIFEST and attempts to execute the downloaded payload. If our overflow payload is crafted to be a valid (unsigned) iBSS binary, and RSA is already patched, it may execute directly.

**Fix E - Patch a different target that sub_100013FD0 doesn't reset**  
Instead of da0, find a SRAM location written AFTER sub_100013FD0 runs that we can control. Candidates:  
- 0xD82 (DFU state machine) - written by sub_100014130 after SETUP
- 0xD84 (size limit) - written by sub_100013FD0 itself  
- 0xCCC (interface count) - read by sub_1000130F4, if 0 > returns -1 > triggers alt path

**Fix F - Pre-position patch bytes using TOCTOU overflow directly**  
The race itself delivers 0x800 bytes starting at da0+0. After the race, da0 is still = rsa_verify until sub_100013FD0 runs. The race already wrote buf[0..0x7FF] to SRAM at 0x1FC022000. If we position the RSA patch bytes at offset (rsa_verify - da0_real) within the overflow payload, and rsa_verify is reachable that way... but rsa_verify (0x100024730) < da0_real (0x1FC022000+), so the offset wraps. Not directly reachable.

**Fix G - Two-stage TOCTOU: race again during stage 2**  
Run the race again while stage 2 is connected. Race fires > bytes_received reset > da0 still = rsa_verify (0x570/0x580 flags still set) > stage 2's data callback fires > patch lands. The stage 2 thread is already polling - if the race re-fires during stage 2's DNLOAD, it might work.

---

## 7. Image4 / Signature Validation Chain

```
img4_validate_manifest (sub_100006324)
  > sub_10000ABD4: check 0x1FC0218E6 bit 6 (security state)
  > if development (CPFM:03): relaxed validation
  
FUN_1000244D0 (RSA/ECDSA dispatch)
  > loads fn ptr from crypto vtable at 0x100030940
  > 0x100030940 = 0x100024730 (rsa_pkcs1_verify)
  > vtable in ROM - cannot be patched via overflow

Image4 validator chain:
  FUN_10002394C > FUN_100023A88 > FUN_100024BBC
  > rsa_pkcs1_verify (0x100024730) - PATCH TARGET
```

---

## 8. Additional Checks Found

### Check 1 - CCC (interface count) gate in sub_1000130F4
```c
if (MEMORY[0x1FC022CCC] == 0) return 0xFFFFFFFF;
```
If overflow zeros 0xCCC (buf+0xCCC = 0xCCC), sub_1000130F4 returns -1 > sub_10000C440 calls sub_10000C428 > DFU fails to initialize. **Must keep 0xCCC non-zero.** Offset 0xCCC is past our OVFL_TOTAL (0xDA8) so currently safe.

### Check 2 - D81 flag in sub_100014054
```c
if (MEMORY[0x1FC022D81] == 1) return 0;  // already initialized, skip
```
If 0xD81 = 1, dfu_endpoint_setup returns immediately without resetting da0. **buf[0xD81] = 1 would prevent dfu_endpoint_setup from resetting da0.** Offset 0xD81 is within OVFL_TOTAL (< 0xDA8). **This is a new unexplored approach.**

### Check 3 - 0x534 USB active gate in sub_10000BB64
```c
if (MEMORY[0x1FC022534] == 0) return sub_10000BAF0(a1, -1);
```
Must be non-zero for USB event processing. buf+0x534 is inside the DFU buffer - calloc zeroes it. But it's set by sub_10000AF98 during USB init and restored on re-enumeration. May need `buf[0x534] = 1`.

### Check 4 - wLength bounds in dfu_control_request_handler
```c
if (wLength < 0x801) > accepted (wLength ≤ 0x800)
if (wLength ≥ 0x801) > error (wLength 0x801-0xFFFF rejected)
```
Maximum per-DNLOAD is 0x800 bytes. The race causes overflow not by exceeding wLength but by resetting bytes_received mid-transfer.

### Check 5 - D82 state machine in CLRSTATUS path
```c
if (MEMORY[0x1FC022D82] != '\a') goto error;  // must be dfuMANIFEST (7)
ptr = da0 + (bytes_received - 0x10);
*ptr = 0; *(ptr+8) = 0;  // 16-byte zero write
```
DFU_CLRSTATUS zero-write only fires in dfuMANIFEST state. Could write 16 zeros anywhere da0 points, at offset bytes_received-0x10.

---

## 9. Most Promising Unexplored Finding

**buf[0xD81] = 1 - dfu_endpoint_setup skip flag**

From sub_100014054 (dfu_endpoint_setup):
```c
if (MEMORY[0x1FC022D81] == 1) return 0;  // already init - SKIP EVERYTHING
```

If the overflow sets buf[0xD81] = 1:
- da0 is NOT reset (dfu_endpoint_setup returns immediately)
- USB endpoint buffer is NOT reset
- All other fields remain as-is

This is different from 0x570 and 0x580:
- 0x570 prevents the *outer* re-init call from sub_10000C440
- 0x580 prevents pool re-init from sub_10000C4B4
- **0xD81 prevents dfu_endpoint_setup itself** - the deepest guard

And crucially: **sub_100013FD0 does NOT check 0xD81**. sub_100013FD0 resets da0 regardless. But if 0xD81=1, the USB endpoint is not re-registered on re-enumeration. The device may not enumerate properly. **Needs testing.**

**Combined flag strategy for next run:**
```c
buf[0x534] = 1;   // USB active flag - keeps event loop running
buf[0x570] = 1;   // outer re-init skip
buf[0x580] = 1;   // pool re-init skip  
buf[0xD80] = 1;   // DFU state byte - prevents spin-wait
buf[0xD81] = 1;   // dfu_endpoint_setup skip - NEW, prevents da0 reset
                  // from re-enumeration path
buf[0xDA0..0xDA7] = 0x100024730  // da0 > rsa_pkcs1_verify
```

The key question: does sub_100013FD0 still reset da0 when called from the stage 2 DNLOAD SETUP? Yes - it does. The 0xD81 flag only bypasses dfu_endpoint_setup, not sub_100013FD0.

**The definitive fix is to not trigger sub_100013FD0 at all for stage 2.** That means either:
1. Sending stage 2 data without a SETUP packet (raw OUT - non-standard)
2. Having stage 2 complete WITHIN the same DFU session as the race (same USB connection)
3. Finding a code path that reads da0 without calling sub_100013FD0 first

---

## 10. iBSS / iBEC / iBoot Patch Targets (Confirmed)

Once SecureROM bypass is achieved, the chain continues:

### iBSS (d27, decrypted):
| Offset | Original | Patch | Effect |
|---|---|---|---|
| 0x023714 | 0x540002C0 (B.EQ) | 0x14000012 (B) | Always take Memz trusted path |
| 0x06F8D4 | 0x540000A0 (B.EQ) | 0x14000005 (B) | Always skip trust evaluator |
| 0x070210 | 0x540000A1 (B.NE) | 0xD503201F (NOP) | Fall into boot path |
| 0x0222E8 | 0x540005C1 (B.NE) | 0xD503201F (NOP) | Skip img4 tag check |

### iBEC (d27, decrypted) - identical offsets to iBSS:
Same 4 patches, same offsets, confirmed from binary analysis.

### iBoot (d27, load base 0x86BA00000):
| File Offset | Runtime | Patch | Effect |
|---|---|---|---|
| 0x000705C0 | 0x86BA705C0 | NOP (0x1F2003D5) | Zero actlock LDRB W9 |
| 0x00070720 | 0x86BA70720 | B always (0x14000008) | Force boot-continues path |
| 0x000B8B60 | 0x86BAB8B60 | NOP (0x1F2003D5) | Bypass sig verify CBZ |
| 0x0011CDB0 | 0x86BB1CDB0 | MOV W0,#1 + RETAB | Hash verify always returns 1 |

---

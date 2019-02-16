#
# IDA Loader for Datatrak ROMs
# Based on idaneogeo - https://github.com/neogeodev/IDANeoGeo/
#

import idaapi
import struct

FORMAT_NAME="Datatrak 68k"

SEEK_CUR=0
SEEK_SET=1
SEEK_END=2

def accept_file(li, filename):
	# TODO add comments from IDA PDF loader demo

	return FORMAT_NAME


def name_cmt_long(ea, name, cmt):
	idaapi.set_name(ea, name)
	idaapi.set_cmt(ea, cmt, False) # nonrepeatable comment
	idaapi.doDwrd(ea, 4)
	idaapi.set_offset(ea, 0, 0)


def hwreg(ea, name, comment):
	idaapi.doDwrd(ea, 4)
	idaapi.set_name(ea, name)
	idaapi.set_cmt(ea, cmt, True) # repeatable comment



def do_68k_vectors():
	# Name the vectors
	name_cmt_long(0x00, "InitSP", "Intial stack pointer")
	name_cmt_long(0x04, "InitPC", "Initial program counter")
	name_cmt_long(0x08, "", "Bus Error")
	name_cmt_long(0x0C, "", "Address Error")
	name_cmt_long(0x10, "", "Illegal instruction")
	name_cmt_long(0x14, "", "Divide-by-Zero")
	name_cmt_long(0x18, "", "CHK instruction")
	name_cmt_long(0x1C, "", "TRAPV instruction")
	name_cmt_long(0x20, "", "Privilege violation")
	name_cmt_long(0x24, "", "Trace")
	name_cmt_long(0x28, "", "Line 1010 emulation")
	name_cmt_long(0x2C, "", "Line 1111 emulation")
	name_cmt_long(0x30, "", "Reserved")
	name_cmt_long(0x34, "", "Reserved")
	name_cmt_long(0x38, "", "Reserved")
	name_cmt_long(0x3C, "", "Uninitialized interrupt")
	name_cmt_long(0x40, "", "Reserved")
	name_cmt_long(0x44, "", "Reserved")
	name_cmt_long(0x48, "", "Reserved")
	name_cmt_long(0x4C, "", "Reserved")
	name_cmt_long(0x50, "", "Reserved")
	name_cmt_long(0x54, "", "Reserved")
	name_cmt_long(0x58, "", "Reserved")
	name_cmt_long(0x5C, "", "Reserved")
	name_cmt_long(0x50, "", "Spurious interrupt")
	name_cmt_long(0x64, "", "Level 1 interrupt")
	name_cmt_long(0x68, "", "Level 2 interrupt")
	name_cmt_long(0x6C, "", "Level 3 interrupt")
	name_cmt_long(0x60, "", "Level 4 interrupt")
	name_cmt_long(0x74, "", "Level 5 interrupt")
	name_cmt_long(0x78, "", "Level 6 interrupt")
	name_cmt_long(0x7C, "", "Level 7 interrupt / NMI")

	for i in range(16):
		name_cmt_long(0x80 + (i*4), "", "TRAP #%d" % i)

	for a in range(0xC0, 0xFD, 4):
		name_cmt_long(a, "", "Reserved")

	for i in range(64, 256):
		name_cmt_long(i*4, "", "USER vector %d" % i)


def do_hardware_regs():
	## AD converter
	hwreg(0x240001, "ADC_READ", "ADC result (read)")
	
	## Unknown
	#hwreg(0x240100, "UNK0100", "Unknown hardware")

	## RF phase detector
	hwreg(0x240200, "RF_PHASE_HI", "RF phase, high nibble")
	hwreg(0x240201, "RF_PHASE_LO", "RF phase, low byte")

	## UART
	hwreg(0x240300, "UART_MRA",	      "R/W: Mode register A (MR1A, MR2A)")
	hwreg(0x240302, "UART_SRA_CSRA",  "R: Status Reg A (SRA)\nW: Clock Select Reg A (CSRA)")
	hwreg(0x240304, "UART_BRGT_CRA",  "R: BRG Test\nW: Command Reg A (CRA)")
	hwreg(0x240306, "UART_RHRA_THRA", "R: RX Holding Reg A (RHRA)\nW: TX Holding Reg A (THRA)")
	hwreg(0x240308, "UART_IPCR_ACR",  "R: Input port change reg (IPCR)\nW: Aux ctl register (ACR)")
	hwreg(0x24030A, "UART_ISR_IMR",   "R: Interrupt status (ISR)\nW: Interrupt mask (IMR)")
	hwreg(0x24030C, "UART_CTU_CTUR",  "R: Counter-timer upper (CTU)\nW: C/T Upper preset (CTUR)")
	hwreg(0x24030E, "UART_CTL_CTLR",  "R: Counter-timer lower (CTL)\nW: C/T Lower preset (CTLR)")
	
	hwreg(0x240310, "UART_MRB",	      "R/W: Mode register B (MR1B, MR2B)")
	hwreg(0x240312, "UART_SRB_CSRB",  "R: Status Reg B (SRB)\nW: Clock Select Reg B (CSRB)")
	hwreg(0x240314, "UART_T116_CRB",  "R: 1x/16x Test\nW: Command Reg B (CRB)")
	hwreg(0x240316, "UART_RHRB_THRB", "R: RX Holding Reg B (RHRB)\nW: TX Holding Reg B (THRB)")
	hwreg(0x240318, "UART_IVR",       "R: Interrupt vector register")
	hwreg(0x24031A, "UART_IP_OPCR",   "R: Input ports IP0-IP6\nW: Output port config register (OPCR)")
	hwreg(0x24031C, "UART_CSTART_SOPB",  "R: Start Counter command\nW: Set Output Port Bits")
	hwreg(0x24031E, "UART_CSTOP_ROPB",  "R: Stop Counter command\nW: Reset Output Port Bits")

	## Unknown
	#hwreg(0x240500, "UNK0500", "Unknown hardware")

	## Unknown
	#hwreg(0x240700, "UNK0700", "Unknown hardware")
	
	## Unknown
	#hwreg(0x240800, "UNK0800", "Unknown hardware")



def load_file(li, neflags, format):
	# Check the format we've been asked to load
	if format != FORMAT_NAME:
		return 0

	# Datatrak 68K - set processor type
	idaapi.set_processor_type("68000", SETPROC_ALL | SETPROC_FATAL)

	# Add segments
	idaapi.add_segm(0, 0x000000, 0x03FFFF, "ROM", "CODE")		# TODO validate ROM area
	idaapi.add_segm(0, 0x200000, 0x21FFFF, "RAM", "DATA")		# TODO validate RAM area
	idaapi.add_segm(0, 0x220000, 0x23FFFF, "RAM2", "DATA")		# TODO validate this, it's here just to fill space
	idaapi.add_segm(0, 0x240000, 0x2400FF, "IO_ADC", "DATA")	# A/D converter
	idaapi.add_segm(0, 0x240100, 0x2401FF, "IO_UNK_01", "DATA")	# 
	idaapi.add_segm(0, 0x240200, 0x2402FF, "IO_RFPHA", "DATA")	# RF phase detector
	idaapi.add_segm(0, 0x240300, 0x2403FF, "IO_UART", "DATA")	# Dual UART
	idaapi.add_segm(0, 0x240400, 0x2404FF, "IO_UNK_04", "DATA")	# 
	idaapi.add_segm(0, 0x240500, 0x2405FF, "IO_UNK_05", "DATA")	# 
	idaapi.add_segm(0, 0x240600, 0x2406FF, "IO_UNK_06", "DATA")	# 
	idaapi.add_segm(0, 0x240700, 0x2407FF, "IO_UNK_07", "DATA")	# 
	idaapi.add_segm(0, 0x240800, 0x2408FF, "IO_UNK_08", "DATA")	# 
	idaapi.add_segm(0, 0x240900, 0x24FFFF, "IO_UNKNOWN", "DATA")	# 

	# Seek to EOF and get filesize
	li.seek(0, 2)
	size = li.tell()

	# Seek back to start of file, read the file into memory
	li.seek(0)
	file_data = li.read(size)
	idaapi.mem2base(file_data, 0, size)	# data,start,end
	
	do_68k_vectors()


	# Get the initial program counter
	initPC = struct.unpack('>L', bytearray(file_data[4:8]))[0]

	# Hunt down the DATA segment initialiser, starting at the reset vector
	pattern = [
			0x41, 0xF9, 0x00, 0x20, 0x00, 0x00,			# LEA    (0x200000).L, A0     ; start of dseg in RAM
			0x20, 0x3C, 0x00, None, None, None,			# MOVE.L #EndOfDataSeg, D0    ; end of dseg in RAM
			0x90, 0x88,									# SUB.L  A0, D0               ; D0 = D0 - A0
			0x43, 0xF9, 0x00, None, None, None,			# LEA    (StartOfData), A1    ; start of dseg initialisation data
			0x53, 0x80,									# SUBQ.L #1, D0               ; D0 --
			0x10, 0xD9,									# MOVE.B (A1)+, (A0)+         ; *a0++ = *a1++
			0x51, 0xC8, 0xFF, 0xFC						# DBF    D0, $-2              ; decrement d0, branch if >= 0
			]
	sh_reg = [0x00]*len(pattern)

	for addr in range(initPC, initPC + 0x100):
		# shift in next byte
		sh_reg = sh_reg[1:]
		sh_reg.append(ord(file_data[addr]))

		# check if we've found a match
		match = True
		for i in range(len(pattern)):
			if pattern[i] is not None and pattern[i] != sh_reg[i]:
				match = False
				break

		# exit the search loop if we found a match
		if match:
			break

	if match:
		# If we've exited the loop and have a match, fish the DSEG addresses
		# out of the instruction parameters.
		dsegRamStart = struct.unpack(">L", bytearray(sh_reg[2:6]))[0]
		dsegRamEnd   = struct.unpack(">L", bytearray(sh_reg[8:12]))[0]
		dsegRomStart = struct.unpack(">L", bytearray(sh_reg[16:20]))[0]

		print("DSEG RAM Start %08X" % dsegRamStart)
		print("DSEG RAM End   %08X" % dsegRamEnd)
		print("DSEG ROM Start %08X" % dsegRomStart)

		# Calculate initialised data segment end and end of the idata in ROM
		dsegLen = dsegRamEnd - dsegRamStart
		dsegRomEnd = dsegRomStart + dsegLen

		# Load the idata into RAM from the appropriate part of the ROM file
		idaapi.mem2base(file_data[dsegRomStart:dsegRomEnd], dsegRamStart, dsegRamEnd)

		# TODO: Designate the source idata as ROM DATA
		idaapi.add_segm(0, dsegRomStart, dsegRomEnd, "DATAINIT", "DATA")
	else:
		print("No Match")

	"""
	# ???
	idaapi.do_unknown(0x3C0000, 1)
	idaapi.doByte(0x3C0000, 1)
	idaapi.set_name(0x3C0000, "REG_VRAMADDR")
	#idaapi.set_cmt(0x3C0000, "Pouet.", 1)
	"""

	return 1

# vim: ts=4 sw=4 noet

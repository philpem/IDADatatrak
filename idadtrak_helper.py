from idautils import *
from idaapi import *
from idc import *

print("Converting all MOVEA.L first-args into address references...")
for funcea in Functions(0, 0x3FFFF):
    functionName = GetFunctionName(funcea)
    #print("FUNC '%s' = %08X" % (functionName, funcea))

    # A "Chunk" is a block of code in a function
    for (startea, endea) in Chunks(funcea):
        #print("Chunk %08X -> %08X" % (startea, endea))

        # A "Head" is an instruction inside a chunk
        for ea in Heads(startea, endea):
            #print functionName, ":", "0x%08x"%(head), ":", GetDisasm(head)

            # Look for a MOVEA.L instruction with an immediate source
            if GetMnem(ea) != "movea.l" or get_operand_type(ea, 0) != 5:
                continue

            # Set
            op_plain_offset(ea, 0, 0)  # addr, opnum, base


# TODO: Scan for switch idioms

# TODO: Scan for task table



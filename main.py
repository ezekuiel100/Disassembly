import pefile
from capstone import *

pe = pefile.PE("main.exe")
text_section = None

for section in pe.sections:
    if b".text" in section.Name:
        text_section = section
        break

if text_section is None:
   raise Exception("Seção .text não encontrada!")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

CODE = text_section.get_data()
addr = text_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

with open("saida.asm" , "w") as f:
 for i in md.disasm(CODE, addr):
    f.write(f"{i.address:x}: {i.mnemonic} {i.op_str}\n") 

SECTIONS
{
	.text :
	{
        *(.text.GetDLL)
		*(.text.GetModuleBaseAddress)
		*(.text.GetExportAddress)
		*(.text.shellcode)
		*(.text.lzo1z_decompress)
	}
}

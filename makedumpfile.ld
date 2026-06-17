SECTIONS
{
	.init_ksyms ALIGN(8) : {
		__start_init_ksyms = .;
		KEEP(*(.init_ksyms*))
		__stop_init_ksyms = .;
	}

	.init_ktypes ALIGN(8) : {
		__start_init_ktypes = .;
		KEEP(*(.init_ktypes*))
		__stop_init_ktypes = .;
	}
}
INSERT AFTER .data;


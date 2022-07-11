#ifndef __C3_OPTIN_MODULES_H__
#define __C3_OPTIN_MODULES_H__


#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

const char* c3_enable_modules[]= { "example_module",
	"ptp",
	"pps_core",
	"crc_ccitt"
	//"x_tables" //BUG: unable to handle page fault for address: ffffaae781e458c0
	//"unix" //SMB, and NMB services & mount command fails with this
	//"ip_tables" //non-canonical decoded address{ address_before : 0x52c6c2e56922aabc decoded address: 0x7fffdd596922aabc }
	//"af_packet" //panic BUG: unable to handle page fault for address: ffffaae781e448c0 ; ICV mismatch on write to ffffffffa0104088, this_icv=0 != stored_icv=adcb8b89a0104088
	//"ipv6" //panic. non-canonical addr a5? ICV mismatch on write to ffffffffa00e1648, this_icv=0 != stored_icv=adcb8b89a00e1648 (rip: 0xffffffff811b6890)
	//read integrity?
};

#define NUMBER_OF_C3_MODULES COUNT_OF(c3_enable_modules)

#endif //__C3_OPTIN_MODULES_H__

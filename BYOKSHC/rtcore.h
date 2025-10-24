struct RtcoreRWStruct {
	BYTE	pad1[8]; // 0 --> 8
	DWORD64 Address1; // 8 --> 16
	BYTE	pad2[4]; // 16--> 20
	DWORD32 offsetStrano; // 20 --> 24
	DWORD32 castControl; // 24 --> 28
	DWORD32 Value; // 28 --> 36
	BYTE	pad3[16];
};

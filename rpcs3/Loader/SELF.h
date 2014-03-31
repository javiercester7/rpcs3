#pragma once
#include "Loader.h"

struct SceHeader
{
	u32 se_magic;
	u32 se_hver;
	u16 se_flags;
	u16 se_type;
	u32 se_meta;
	u64 se_hsize;
	u64 se_esize;

	void Load(vfsStream& f)
	{
		se_magic		= Read32(f);
		se_hver			= Read32(f);
		se_flags		= Read16(f);
		se_type			= Read16(f);
		se_meta			= Read32(f);
		se_hsize		= Read64(f);
		se_esize		= Read64(f);
	}

	void Show()
	{
		ConLog.Write(fmt::fmt("Magic: %08x",	se_magic));
		ConLog.Write("Class: ???",				"SELF");
		ConLog.Write(fmt::fmt("hver: 0x%08x",	se_hver));
		ConLog.Write(fmt::fmt("flags: 0x%04x",	se_flags));
		ConLog.Write(fmt::fmt("type: 0x%04x",	se_type));
		ConLog.Write(fmt::fmt("meta: 0x%08x",	se_meta));
		ConLog.Write(fmt::fmt("hsize: 0x%llx",	se_hsize));
		ConLog.Write(fmt::fmt("esize: 0x%llx",	se_esize));
	}

	bool CheckMagic() const { return se_magic == 0x53434500; }
};

struct SelfHeader
{
	u64 se_htype;
	u64 se_appinfooff;
	u64 se_elfoff;
	u64 se_phdroff;
	u64 se_shdroff;
	u64 se_secinfoff;
	u64 se_sceveroff;
	u64 se_controloff;
	u64 se_controlsize;
	u64 pad;

	void Load(vfsStream& f)
	{
		se_htype		= Read64(f);
		se_appinfooff	= Read64(f);
		se_elfoff		= Read64(f);
		se_phdroff		= Read64(f);
		se_shdroff		= Read64(f);
		se_secinfoff	= Read64(f);
		se_sceveroff	= Read64(f);
		se_controloff	= Read64(f);
		se_controlsize	= Read64(f);
		pad				= Read64(f);
	}

	void Show()
	{
		ConLog.Write(fmt::fmt("header type: 0x%llx",					se_htype));
		ConLog.Write(fmt::fmt("app info offset: 0x%llx",				se_appinfooff));
		ConLog.Write(fmt::fmt("elf offset: 0x%llx",						se_elfoff));
		ConLog.Write(fmt::fmt("program header offset: 0x%llx",			se_phdroff));
		ConLog.Write(fmt::fmt("section header offset: 0x%llx",			se_shdroff));
		ConLog.Write(fmt::fmt("section info offset: 0x%llx",			se_secinfoff));
		ConLog.Write(fmt::fmt("sce version offset: 0x%llx",				se_sceveroff));
		ConLog.Write(fmt::fmt("control info offset: 0x%llx",			se_controloff));
		ConLog.Write(fmt::fmt("control info size: 0x%llx",				se_controlsize));
	}
};

class SELFLoader : public LoaderBase
{
	vfsStream& self_f;

	SceHeader sce_hdr;
	SelfHeader self_hdr;

public:
	SELFLoader(vfsStream& f);

	virtual bool LoadInfo();
	virtual bool LoadData(u64 offset = 0);
};
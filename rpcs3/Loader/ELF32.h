#pragma once
#include "Loader.h"

struct Elf32_Ehdr
{
	u32 e_magic;
	u8  e_class;
	u8  e_data;
	u8  e_curver;
	u8  e_os_abi;
	u64 e_abi_ver;
	u16 e_type;
	u16 e_machine;
	u32 e_version;
	u16 e_entry;
	u32 e_phoff;
	u32 e_shoff;
	u32 e_flags;
	u16 e_ehsize;
	u16 e_phentsize;
	u16 e_phnum;
	u16 e_shentsize;
	u16 e_shnum;
	u16 e_shstrndx;

	void Show()
	{
#ifdef LOADER_DEBUG
		ConLog.Write("Magic: ???",								fmt::fmt("%08x",e_magic));
		ConLog.Write("Class: ???",								"ELF32");
		ConLog.Write("Data: ???",								Ehdr_DataToString(e_data).ToStdString());
		ConLog.Write("Current Version: ???",					e_curver);
		ConLog.Write("OS/ABI: ???",								Ehdr_OS_ABIToString(e_os_abi).ToStdString());
		ConLog.Write("ABI version: ???",						e_abi_ver);
		ConLog.Write("Type: ???",								Ehdr_TypeToString(e_type).ToStdString());
		ConLog.Write("Machine: ???",							Ehdr_MachineToString(e_machine).ToStdString());
		ConLog.Write("Version: ???",							e_version);
		ConLog.Write("Entry point address: 0x%x",				fmt::fmt("%x",e_entry));
		ConLog.Write("Program headers offset: 0x???",			fmt::fmt("%x",e_phoff));
		ConLog.Write("Section headers offset: 0x???",			fmt::fmt("%08x",e_shoff));
		ConLog.Write("Flags: 0x???",							fmt::fmt("%x",e_flags));
		ConLog.Write("Size of this header: ???",				e_ehsize);
		ConLog.Write("Size of program headers: ???",			e_phentsize);
		ConLog.Write("Number of program headers: ???",			e_phnum);
		ConLog.Write("Size of section headers: ???",			e_shentsize);
		ConLog.Write("Number of section headers: ???",			e_shnum);
		ConLog.Write("Section header string table index: ???",	e_shstrndx);
#endif
	}

	bool IsLittleEndian() const
	{
		return e_data == 1;
	}

	void Load(vfsStream& f)
	{
		e_magic		= Read32(f);
		e_class		= Read8(f);
		e_data		= Read8(f);
		e_curver	= Read8(f);
		e_os_abi	= Read8(f);

		if(IsLittleEndian())
		{
			e_abi_ver	= Read64LE(f);
			e_type		= Read16LE(f);
			e_machine	= Read16LE(f);
			e_version	= Read32LE(f);
			e_entry		= Read32LE(f);
			e_phoff		= Read32LE(f);
			e_shoff		= Read32LE(f);
			e_flags		= Read32LE(f);
			e_ehsize	= Read16LE(f);
			e_phentsize = Read16LE(f);
			e_phnum		= Read16LE(f);
			e_shentsize = Read16LE(f);
			e_shnum		= Read16LE(f);
			e_shstrndx  = Read16LE(f);
		}
		else
		{
			e_abi_ver	= Read64(f);
			e_type		= Read16(f);
			e_machine	= Read16(f);
			e_version	= Read32(f);
			e_entry		= Read32(f);
			e_phoff		= Read32(f);
			e_shoff		= Read32(f);
			e_flags		= Read32(f);
			e_ehsize	= Read16(f);
			e_phentsize = Read16(f);
			e_phnum		= Read16(f);
			e_shentsize = Read16(f);
			e_shnum		= Read16(f);
			e_shstrndx  = Read16(f);
		}
	}

	bool CheckMagic() const { return e_magic == 0x7F454C46; }
	u32 GetEntry() const { return e_entry; }
};

struct Elf32_Desc
{
	u32 revision;
	u32 ls_size;
	u32 stack_size;
	u32 flags;

	void Load(vfsStream& f)
	{
		revision = Read32(f);
		ls_size = Read32(f);
		stack_size = Read32(f);
		flags = Read32(f);
	}

	void LoadLE(vfsStream& f)
	{
		revision = Read32LE(f);
		ls_size = Read32LE(f);
		stack_size = Read32LE(f);
		flags = Read32LE(f);
	}
};

struct Elf32_Note
{
	u32 namesz;
	u32 descsz;
	u32 type;
	u8 name[8];
	union
	{
		Elf32_Desc desc;
		char desc_text[32];
	};

	void Load(vfsStream& f)
	{
		namesz = Read32(f);
		descsz = Read32(f);
		type = Read32(f);
		f.Read(name, 8);

		if(descsz == 32)
		{
			f.Read(desc_text, descsz);
		}
		else
		{
			desc.Load(f);
		}
	}

	void LoadLE(vfsStream& f)
	{
		namesz = Read32LE(f);
		descsz = Read32LE(f);
		type = Read32LE(f);
		f.Read(name, 8);

		if(descsz == 32)
		{
			f.Read(desc_text, descsz);
		}
		else
		{
			desc.Load(f);
		}
	}
};

struct Elf32_Shdr
{
	u32 sh_name; 
	u32 sh_type;
	u32 sh_flags;
	u32 sh_addr;
	u32 sh_offset;
	u32 sh_size;
	u32 sh_link;
	u32 sh_info;
	u32 sh_addralign;
	u32 sh_entsize;

	void Load(vfsStream& f)
	{
		sh_name			= Read32(f);
		sh_type			= Read32(f);
		sh_flags		= Read32(f);
		sh_addr			= Read32(f);
		sh_offset		= Read32(f);
		sh_size			= Read32(f);
		sh_link			= Read32(f);
		sh_info			= Read32(f);
		sh_addralign	= Read32(f);
		sh_entsize		= Read32(f);
	}

	void LoadLE(vfsStream& f)
	{
		sh_name			= Read32LE(f);
		sh_type			= Read32LE(f);
		sh_flags		= Read32LE(f);
		sh_addr			= Read32LE(f);
		sh_offset		= Read32LE(f);
		sh_size			= Read32LE(f);
		sh_link			= Read32LE(f);
		sh_info			= Read32LE(f);
		sh_addralign	= Read32LE(f);
		sh_entsize		= Read32LE(f);
	}

	void Show()
	{
#ifdef LOADER_DEBUG
		ConLog.Write(fmt:fmt("Name offset: %x",		sh_name));
		ConLog.Write(fmt:fmt("Type: %d",			sh_type));
		ConLog.Write(fmt:fmt("Addr: %x",			sh_addr));
		ConLog.Write(fmt:fmt("Offset: %x",			sh_offset));
		ConLog.Write(fmt:fmt("Size: %x",			sh_size));
		ConLog.Write(fmt:fmt("EntSize: %d",			sh_entsize));
		ConLog.Write(fmt:fmt("Flags: %x",			sh_flags));
		ConLog.Write(fmt:fmt("Link: %x",			sh_link));
		ConLog.Write(fmt:fmt("Info: %d",			sh_info));
		ConLog.Write(fmt:fmt("Address align: %x",	sh_addralign));
#endif
	}
};

struct Elf32_Phdr
{
	u32	p_type;
	u32	p_offset;
	u32	p_vaddr;
	u32	p_paddr;
	u32	p_filesz;
	u32	p_memsz;
	u32	p_flags;
	u32	p_align;

	void Load(vfsStream& f)
	{
		p_type		= Read32(f);
		p_offset	= Read32(f);
		p_vaddr		= Read32(f);
		p_paddr		= Read32(f);
		p_filesz	= Read32(f);
		p_memsz		= Read32(f);
		p_flags		= Read32(f);
		p_align		= Read32(f);
	}

	void LoadLE(vfsStream& f)
	{
		p_type		= Read32LE(f);
		p_offset	= Read32LE(f);
		p_vaddr		= Read32LE(f);
		p_paddr		= Read32LE(f);
		p_filesz	= Read32LE(f);
		p_memsz		= Read32LE(f);
		p_flags		= Read32LE(f);
		p_align		= Read32LE(f);
	}

	void Show()
	{
#ifdef LOADER_DEBUG
		ConLog.Write("Type: ???",								Phdr_TypeToString(p_type).ToStdString());
		ConLog.Write(fmt::fmt("Offset: 0x%08x",					p_offset));
		ConLog.Write(fmt::fmt("Virtual address: 0x%08x",		p_vaddr));
		ConLog.Write(fmt::fmt("Physical address: 0x%08x",		p_paddr));
		ConLog.Write(fmt::fmt("File size: 0x%08x",				p_filesz));
		ConLog.Write(fmt::fmt("Memory size: 0x%08x",			p_memsz));
		ConLog.Write("Flags: ???",								Phdr_FlagsToString(p_flags).ToStdString());
		ConLog.Write(fmt::fmt("Align: 0x%x",					p_align));
#endif
	}
};

class ELF32Loader : public LoaderBase
{
	vfsStream& elf32_f;

public:
	Elf32_Ehdr ehdr;
	wxArrayString shdr_name_arr;
	Array<Elf32_Shdr> shdr_arr;
	Array<Elf32_Phdr> phdr_arr;

	ELF32Loader(vfsStream& f);
	~ELF32Loader() {Close();}

	virtual bool LoadInfo();
	virtual bool LoadData(u64 offset);
	virtual bool Close();

private:
	bool LoadEhdrInfo();
	bool LoadPhdrInfo();
	bool LoadShdrInfo();

	bool LoadEhdrData(u64 offset);
	bool LoadPhdrData(u64 offset);
	bool LoadShdrData(u64 offset);
};

void WriteEhdr(wxFile& f, Elf32_Ehdr& ehdr);
void WritePhdr(wxFile& f, Elf32_Phdr& phdr);
void WriteShdr(wxFile& f, Elf32_Shdr& shdr);
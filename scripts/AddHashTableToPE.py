from ctypes import c_uint64, c_uint32
import struct
import lief
import argparse
import mmap
import os
import struct
import zlib
import xxhash

class HashTableItem:
    key = 0
    value = 0
    next_index = None
    
    def __init__(self, key, value, next_index):
        self.key = key
        self.value = value
        self.next_index = next_index

    def __bytes__(self):
        return struct.pack("QLL", self.key, self.value, self.next_index if self.next_index != None else 0xFFFFFFFF)

    # To print the items of hash map
    def __str__(self):
        return "0x%x (next: %s): 0x%x\n" % (self.key, str(hex(self.next_index)) if self.next_index != None else "None", self.value)

    def __eq__(self, other):
        if self.key != other.key:
            return False
        if self.value != other.value:
            return False
        if self.next_index != other.next_index:
            return False

        return True

class HashTable:
    table = []
    size = 0
    
    def __init__(self, *args, **kwargs):
        size = kwargs.get("size")
        byte_data = kwargs.get("data")

        if (size != None):
            self.size = size
            self.table = [HashTableItem(0, 0, None) for _ in range(self.size)] # Create table
        elif (byte_data != None):
            self.size = len(byte_data) // 16

            offset = 0
            for i in range(self.size):
                key, val, next = struct.unpack_from("QLL", byte_data, offset=offset)

                if (next == 0xFFFFFFFF):
                    next = None

                offset += struct.calcsize("QLL")
                self.table.append(HashTableItem(key, val, next))
    
    def add_item(self, key, value):
        hash = c_uint64(hash_djb2(key)).value
        index = hash % self.size

        found = self.table[index]

        if found.key == 0:
            self.table[index].key = hash
            self.table[index].value = value
            return self.table[index]
        elif found.value != value:
            while (found.key != 0):
                if (found.next_index == None):
                    new_index = index
                    while (self.table[new_index].key != 0):
                        new_index += 1
                        if (new_index >= self.size):
                            new_index = 0
                        elif (new_index == index):
                            return None
                    self.table[index].next_index = new_index

                found = self.table[index]

                while (found.next_index != None):
                    current_index = found.next_index
                    found = self.table[found.next_index]

            self.table[current_index].key = hash
            self.table[current_index].value = value

            return self.table[current_index]
    
    def search_item(self, key):
        hash = c_uint64(hash_djb2(key)).value
        index = hash % self.size

        found = self.table[index]

        if found.key == hash:
            return found.value
        elif found.key == 0:
            return None
        else:
            while (found.next_index != None):
                found = self.table[found.next_index]
                if (found.key == hash):
                    return found.value

            return None
    
    # To print the items of hash map
    def __str__(self):
        return "".join(str(item) for item in self.table)

    def __len__(self):
        count = 0

        for i in range(self.size):
            if self.table[i].key != 0:
                count += 1

        return count

    def __bytes__(self):
        byte_str = b''

        for i in range(self.size):
            byte_str += bytes(self.table[i])

        return byte_str

    def __eq__(self, other):
        #if (self.size != other.size):
            #return False

        for i in range(self.size):
            if self.table[i] != other.table[i]:
                return False
        return True

def hash_djb2(s):    
   hash = 0x1337133713371337
   for x in s:
      hash = (( hash << 5) + hash) + ord(x)
   
   # NOTE: future me, this is past me.
   #            you are going to fuck up and feel bad
   #            its because of ctypes
   #            trust no one
   return hash

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Path to PE file (.exe, .dll) to add hash table to.")
    parser.add_argument("-o", "--outfile", help="Path to create newly created PE file (.exe, .dll) to.")
    parser.add_argument("-d", "--dump", help="Dump hash table from PE file (.exe, .dll)", \
                            action="store_true")
    return parser.parse_args()

def align(sz, align):
  if sz % align: sz = ((sz + align) // align) * align
  return sz

def pad_data(data, al):
    # return <data> padded with 0 to a size aligned with <al>
    return data + ([0] * (align(len(data), al) - len(data)))

def write_pe_to_file(pe, args):
    # save the resulting PE 
    if(os.path.exists(args.outfile)):
        # little trick here : lief emits no warning when it cannot write because the output
        # file is already opened. Using this function ensure we fail in this case (avoid errors).
        os.remove(args.outfile)

    builder = lief.PE.Builder(pe)
    builder.build()
    builder.write(args.outfile)

def add_section(pe, args, name):
    # Create Hash Table
    table = bytes(create_hash_table(pe))

    # we're going to keep the same alignment as the ones in unpack_PE,
    # because this is the PE we are modifying
    file_alignment = pe.optional_header.file_alignment
    section_alignment = pe.optional_header.section_alignment

    packed_data = list(table) # lief expects a list, not a "bytes" object.
    #packed_data = pad_data(packed_data, file_alignment) # pad with 0 to align with file alignment (removes a lief warning)

    table_section = lief.PE.Section(name)
    table_section.content =  packed_data
    table_section.size = len(packed_data)
    table_section.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                                | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    # We don't need to specify a Relative Virtual Address here, lief will just put it at the end, that doesn't matter.
    pe.add_section(table_section)

    # remove the SizeOfImage, which should change, as we added a section. Lief will compute this for us.
    pe.optional_header.sizeof_image = 0

    write_pe_to_file(pe, args)

    pe.data_directory(lief.PE.DATA_DIRECTORY.ARCHITECTURE).rva = pe.get_section(name).virtual_address
    pe.data_directory(lief.PE.DATA_DIRECTORY.ARCHITECTURE).size = pe.get_section(name).virtual_size


def create_hash_table(pe):
    table = HashTable(size=len(pe.exported_functions))
    count = 0
    
    for exp in pe.exported_functions:
        # Ordinal only export
        # TODO: not this
        if (exp.name == None):
            continue

        table.add_item(exp.name, exp.address)
        count += 1

    print(table)

    #print(hex(table.search_item("NtAllocateVirtualMemory")))
    print(len(table))
    print(count)

    print (table == HashTable(data=bytes(table)))

    return table


def main(args):
    pe = lief.PE.parse(args.file)
    
    if args.dump:
        for section in pe.sections:
            if section.name.rstrip('\x00') == ".htdata":
                section_data = bytes(section.content)

                table = HashTable(data=section_data)

                #original = create_hash_table(pe)

                print(table)

                print(len(table))
                print(len(section_data))
                print(hex(table.search_item("NtAllocateVirtualMemory")))

                count = 0
                longest_chain = 0
                chain = 0
                found = None

                for i in range(table.size):
                    found = table.table[i]
                    if (found.next_index != None):
                        chain = 0
                        while (found.next_index != None):
                            chain += 1
                            found = table.table[found.next_index]
                        if (chain > longest_chain):
                            longest_chain = chain
                    i += 1

                print (longest_chain)

                #print(table == original)
                return
            print(section.name.rstrip('\x00'))
    else:
        add_section(pe, args, b".htdata")

        write_pe_to_file(pe, args)

        print("[+] Wrote hash table to PE")

if __name__ == "__main__":
    main(get_args())

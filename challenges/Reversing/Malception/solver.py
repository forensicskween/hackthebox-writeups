import pyshark
from Crypto.Cipher import ARC4
import pefile
from corpspace.corp import CorpClass,xor 

def rc4_decrypt(rc4_key,buffer):
    cipher = ARC4.new(rc4_key)
    return cipher.decrypt(buffer)

def parse_pcap(pcap_name):
    hostnames = set()
    stage_1 = []
    stage_2 = []
    buffer = b''
    for pkt in pyshark.FileCapture(pcap_name,display_filter='tcp'):
        if any(layer.layer_name == 'kerberos' for layer in pkt.layers):
            username = pkt.kerberos.get('CNameString')
            hostname = pkt.kerberos.get('realm')
            if username and hostname:
                hostnames.add('.'.join(hostname.split('.')[:-1]))
        elif any(layer.layer_name == 'DATA' for layer in pkt.layers):
            tport = f'{pkt.tcp.srcport}_{pkt.tcp.dstport}'
            if '8000' in tport:
                continue
            elif '31337' in tport:
                if pkt.tcp.srcport == '31337':
                    stage_1.append(bytes.fromhex(pkt.data.data))
            elif '31338' in tport:
                byte_data = bytes.fromhex(pkt.data.data)
                buffer+=byte_data
                if byte_data == b'end':
                    stage_2.append(buffer)
                    buffer = b''
    return list(hostnames),stage_1,stage_2


def parse_stage_1(stage_1,hostname):
    rc4_key = None
    buff = b""
    for pkt in stage_1:
        if rc4_key is None and len(pkt) == 8:
            rc4_key = xor(pkt, hostname)
        else:
            buff += pkt
    plaintext = rc4_decrypt(rc4_key,buff)
    assert len(plaintext) == 7680
    return rc4_key,plaintext

def get_resource_data(pe_filepath,RT_RCDATA=0xA,ID=0x65):
    pe = pefile.PE(pe_filepath)

    # Find resource type 0xA (RT_RCDATA), ID 0x65
    resource_data = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == RT_RCDATA:  # RT_RCDATA
            for subentry in entry.directory.entries:
                if subentry.id == ID:
                    data_rva = subentry.directory.entries[0].data.struct.OffsetToData
                    size = subentry.directory.entries[0].data.struct.Size
                    resource_data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                    return resource_data

    if resource_data is None:
        raise Exception("Resource not found")


def create_dotnet_file(plaintext,resource_data):
    v21 = bytearray(resource_data)
    v12 = bytearray(plaintext)
    for i in range(len(v21)):
        # Copy each byte from v21[0..v19] into v12[5728 + 3504 + i]
        v12[3504 + i] = v21[i]
    return bytes(v12)

def patch_dotnet_dll(stage_1,hostname,pe_filepath,output_name='CorpSpace.dll'):
    rc4_key,plaintext = parse_stage_1(stage_1,hostname)
    encrypted_resource_data = get_resource_data(pe_filepath)
    resource_data = rc4_decrypt(rc4_key,encrypted_resource_data)
    dotnet_file = create_dotnet_file(plaintext,resource_data)
    with open(output_name,'wb') as of:
        of.write(dotnet_file)
    print(f'Wrote {len(dotnet_file)} to {output_name}')
    return rc4_key 




if __name__ == "__main__":
    id_data,stage_1,stage_2 = parse_pcap('capture.pcapng')
    assert len(id_data) == 1
    hostname = list(id_data)[0]
    pe_filepath = 'xQWdrq.exe'
    rc4_key = patch_dotnet_dll(stage_1,hostname.encode(),pe_filepath)
    CorpClass.decrypt_files(stage_2,rc4_key)












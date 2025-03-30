from openpyxl import Workbook
import sys

test_name = [
    ['version','Mhz','tlb pages','cache line bytes', 'mem par', 'scal load'],
    ['Mhz','Null Call','Null IO','stat','open clos','slct TCP','sig inst','sig hndl','fork proc','exec proc','sh proc'],
    ['intgr bit','intgr add','intgr mul','intgr div','intgr mod'],
    ['int64 bit','int64 add','int64 mul','int64 div','int64 mod'],
    ['float add','float mul','float div','float bogo'],
    ['double add','double mul','double div','double bogo'],
    ['2p/0K ctxsw','2p/16K ctxsw','2p/64K ctxsw','8p/16K ctxsw','8p/64K ctxsw','16p/16K ctxsw','16p/64K ctxsw' ],
    ['2p/0K ctxsw','Pipe','AF UNIX','UDP','RPC/UDP','TCP','RPC/TCP','TCP/conn'],
    ['UDP','RPC/UDP','TCP','RPC/TCP','TCP/conn'],
    ['0K File Create','0K File Delete','10K File Create','10K File Delete','Mmap Latency','Prot Fault','Page Fault','100fd selct'],
    ['Pipe','AF UNIX','TCP','File reread','Mmap reread','Bcopy(libc)','Bcopy(hand)','Mem read','Mem write'],
    ['Mhz','L1 $','L2 $','Main mem','Rand mem','Guesses']        
]

section_titles = [
    'Basic system parameters',
    'Processor, Processes - times in microseconds - smaller is better',
    'Basic integer operations - times in nanoseconds - smaller is better',
    'Basic uint64 operations - times in nanoseconds - smaller is better',
    'Basic float operations - times in nanoseconds - smaller is better',
    'Basic double operations - times in nanoseconds - smaller is better',
    'Context switching - times in microseconds - smaller is better',
    '*Local* Communication latencies in microseconds - smaller is better',
    '*Remote* Communication latencies in microseconds - smaller is better',
    'File & VM system latencies in microseconds - smaller is better',
    '*Local* Communication bandwidths in MB/s - bigger is better',
    'Memory latencies in nanoseconds - smaller is better'
]


def extract_section(text, id):
    start_index = text.find(section_titles[id])
    if start_index == -1:
        return None  
    end_index = len(text)
    if id < len(section_titles)-1:
        end_index = text.find(section_titles[id+1], start_index)
    elif id == len(section_titles):
        end_index = len(text)
    
    return text[start_index:end_index].strip()

def extract_data(data, test_id):
    lines = data.split('\n')
    data_list = []
    data_list.append(test_name[test_id])
    for line in lines[5:]:
        if line.startswith('------'):
            continue
        parts = line.strip().split()
        data_list.append(parts[3:])
    return data_list


with open('summary.out', 'rb') as file:
    text = file.read().decode('utf-8', errors='ignore')

wb = Workbook()
ws = wb.active

for test_id in range(len(section_titles)):
    data = extract_section(text, test_id)
    data_list = extract_data(data, test_id)
    ws.append([section_titles[test_id]])
    for row_data in data_list:
        ws.append(row_data)

wb.save("output.xlsx")

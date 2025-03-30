# encoding: gb2312
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

# 返回文本中有用的段落
def extract_section(text, id):
    # 查找部分名称在文本中的索引
    start_index = text.find(section_titles[id])
    if start_index == -1:
        return None  # 如果未找到部分名称，返回 None
    # 从部分名称开始往后找到下一个换行符的索引
    end_index = len(text) # 文件末尾
    if id < len(section_titles)-1:
        end_index = text.find(section_titles[id+1], start_index)
    elif id == len(section_titles):
        end_index = len(text)
    
    # 返回部分名称到下一个换行符之间的文本
    return text[start_index:end_index].strip()

# 解析某一节的数据并将数据部分存储到一个二维列表中
def extract_data(data, test_id):
    # 将数据按行分割成列表
    lines = data.split('\n')
    # 初始化一个二维列表，用于存储数据部分
    data_list = []
    data_list.append(test_name[test_id]) #表头
    # 从第5行开始遍历，提取数据部分
    for line in lines[5:]:
        # 如果遇到分隔线，跳过
        if line.startswith('------'):
            continue
        # 将每行的数据按空格分割成列表
        parts = line.strip().split()
        # 将数据部分添加到二维列表中
        data_list.append(parts[3:])
    return data_list


# 打开文件并读取内容
with open('summary.out', 'rb') as file:
    text = file.read().decode('utf-8', errors='ignore')

# 创建一个 Workbook 对象
wb = Workbook()
# 选择第一个工作表
ws = wb.active

for test_id in range(len(section_titles)):
    # 获取相应段落
    data = extract_section(text, test_id)
    # 提取数据部分并存储在二维列表中
    data_list = extract_data(data, test_id)
    # 写入数据
    ws.append([section_titles[test_id]])
    for row_data in data_list:
        ws.append(row_data)

# 保存文件
wb.save("output.xlsx")

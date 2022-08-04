from binaryninja import *
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import CountVectorizer
from itertools import product
from sklearn.decomposition import PCA
from  collections import Counter
from registers import *
import random
import os
import re
import pickle
import math


def parse_instruction(ins, symbol_map, string_map):
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    operand = []
    if len(parts) > 1:
        operand = parts[1:]
    for i in range(len(operand)):
        symbols = re.split('([0-9A-Za-z]+)', operand[i])
        for j in range(len(symbols)):
            if symbols[j][:2] == '0x' and len(symbols[j]) >= 6:
                if int(symbols[j], 16) in symbol_map:
                    symbols[j] = "symbol"
                elif int(symbols[j], 16) in string_map:
                    symbols[j] = "string"
                else:
                    symbols[j] = "address"
        operand[i] = ' '.join(symbols)
    opcode = parts[0]
    return ' '.join([opcode]+operand)



def get_unique_block_name(file_name, func_name, index):
    tokens = file_name.split('-')
    return tokens[-1] + '.' + func_name + '.' + str(index)

def process_file(f, window_size):
    symbol_map = {}
    string_map = {}
    global basic_block_pairs
    print(f)
    bv = BinaryViewType.get_view_of_file(f)
    for sym in bv.get_symbols():
        symbol_map[sym.address] = sym.full_name
    for string in bv.get_strings():
        string_map[string.start] = string.value

    function_graphs = {}
    total = 0
    for func in bv.functions:
        
        label_dict = {}   
        add_map = {}       
        #print('func:',func.name)
        for block in func:
            #print(block.disassembly_text)
            curr = block.start
            predecessor = curr
            for inst in block:
                label_dict[curr] = bv.get_disassembly(curr)
                
                predecessor = curr
                curr += inst[1]
            basic_block_id = get_unique_block_name(f, func.name, block.index)
            #print('block #', basic_block_id)
            block_text = ""        
            for _, text in label_dict.items():
                block_text = block_text + parse_instruction(text, symbol_map, string_map) + ';'
                #print(text, end=';')
            #print()

            total +=1
            #check if this basic block exists, using the id
            #if not, create a new one
            if (basic_block_id in basic_block_pairs) :
               basic_block_pairs[basic_block_id].append(block_text)
            else :
                basic_block_pairs[basic_block_id] = [block_text]
                #basic_block_pairs[basic_block_id].append()
        
    print('Total number of basic blocks:', total)
    
    """with open('cfg_train.txt', 'a') as w:
        for name, graph in function_graphs.items():
            sequence = random_walk(graph, 40, symbol_map, string_map)
            for s in sequence:
                print(s)
                if len(s) >= 4:
                    for idx in range(0, len(s)):
                        for i in range(1, window_size+1):
                            if idx - i > 0:
                                w.write(s[idx-i] +'\t' + s[idx]  + '\n')
                            if idx + i < len(s):
                                w.write(s[idx] +'\t' + s[idx+i]  + '\n')"""
    # gc.collect()

def main():
    bin_folder = '../../binaries-20K/' 
    file_lst = []
    str_counter = Counter()
    window_size = 1;
    for parent, subdirs, files in os.walk(bin_folder):
        if files:
            for f in files:
                file_lst.append(os.path.join(parent,f))
    i=0
    for f in file_lst:
        print(i,'/', len(file_lst))
        process_file(f, window_size)
        i+=1

    #Keep Either of these two code blocks
    #delete items from the dictionary without pairs
    """for key, pairs in list(basic_block_pairs.items()):
        if(len(pairs)<2):
            del basic_block_pairs[key]"""           

    cap_on_num_of_tokens = 305
    #delete items related to the function that doesn't have matching pair of basic blocks 
    """for key, pairs in list(basic_block_pairs.items()):
        #Delete if number_of_tokens cross a cap
        no_of_tokens = len(re.split(' +|;',pairs[0])) - 1
        if(no_of_tokens > cap_on_num_of_tokens):
            try:
                del basic_block_pairs[key]
            except KeyError:
                pass
            continue
    """
    for key, pairs in list(basic_block_pairs.items()):
        #Delete if number_of_tokens cross a cap    
        if(len(pairs)<2):
            #del all basic_block_pairs entries for this function
            tokens = key.split('.')      
            func_name = tokens[1]
            for jey, _ in list(basic_block_pairs.items()):
                if(jey.split('.')[1] == func_name):
                    del basic_block_pairs[jey]
    return
    

#Global Var for the Dictionary
basic_block_pairs = {}

if __name__ == "__main__":
    main()
    #Write dictionary to a pickle file
    with open('mapping-20K.pkl', 'wb') as handle:
        pickle.dump(basic_block_pairs, handle)







"""def random_walk(g,length, symbol_map, string_map):
    sequence = []
    for n in g:
        if n != -1 and 'text' in g.nodes[n]:
            s = []
            l = 0
            s.append(parse_instruction(g.nodes[n]['text'], symbol_map, string_map))
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    cur = random.choice(nbs)
                    if 'text' in g.nodes[cur]:
                        s.append(parse_instruction(g.nodes[cur]['text'], symbol_map, string_map))
                        l += 1
                    else:
                        break
                else:
                    break
            sequence.append(s)
        if len(sequence) > 5000:
            print("early stop")
            return sequence[:5000]
    return sequence"""
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 11 09:46:13 2019

"""
import os
import json
import csv
import copy
import argparse
import codecs

def assication_1(decafPath, pandaPath, eipPath):
    """
    第一阶段关联，获得污点分析中进程指令地址，保存在EIP.csv文件中
    """
    itemStrSet = set()
    csvFile = open(eipPath, "w")
    csvWriter = csv.writer(csvFile)
    csvWriter.writerow(["proc_name","EIP"])
    with open(decafPath, "r") as jsonFile:
        decafLog = json.load(jsonFile)
        for log in decafLog:
            if "proc_name" not in log.keys():
                continue
            if "func" not in log.keys():
                continue
            if "EIP" not in log["func"].keys():
                continue
            proc_name = log["proc_name"]
            EIP = log["func"]["EIP"]
            if str([proc_name, EIP]) not in itemStrSet:
                # print(proc_name, EIP)
                if EIP >= int("80000000", base=16):
                    continue
                csvWriter.writerow([proc_name, EIP])
                itemStrSet.add(str([proc_name, EIP]))
    csvFile.close()

def findDllDict(mdumpPath, proc_name):
    dllNameSet = set()
    dllDictList = list()
    dllNameAndBaseDict = dict()
    with open(mdumpPath, "r") as jsonFile:
        allLog = json.load(jsonFile)
#        with open("pyrebox.json", "w") as jsonFile:
#            json.dump(allLog, jsonFile, sort_keys=False, indent=4, separators=(',', ':'))

        for log in allLog:
            for dllItem in log["dlls"]:
                if dllItem["proc_name"] == proc_name:
                    dllName = dllItem["mem_full_dll_name"]
                    dllBase = dllItem["dll_base"]
                    if dllName not in dllNameSet and dllName != "":
                        dllNameSet.add(dllName)
                        dllDictList.append(dllItem)
                        dllNameAndBaseDict[dllBase] = dllName
#    print("sum %d" % len(dllNameAndBaseDict))
#    for item in sorted(dllNameAndBaseDict.items(), key=lambda items:int(items[0], 16)):
#        print("%s : %s" % (item[0], item[1]))
    
#    with open("dll_find.json", "w") as jsonFile:
#        json.dump(dllDictList, jsonFile, sort_keys=False, indent=4, separators=(',', ':'))
    
    return dict(sorted(dllNameAndBaseDict.items(), key=lambda items:int(items[0], 16)))

def get_exe_path(dllDict, proc_name):
    for dll in dllDict.values():
        if proc_name in dll:
            return dll

def get_panda_taint(pandaLogs):
    for pandaLog in pandaLogs:
        if "string_tainted" in pandaLog.keys():
            tainted_bytes = pandaLog["string_tainted"]["tainted_bytes"]
            tainted_string = pandaLog["string_tainted"]["tainted_string"]
            return tainted_bytes, tainted_string
    
def findAddrDisasDict(pandaLogs):
    disasDict = dict()
    addrDisasDict = dict()
    for pandaLog in pandaLogs:
        if "string_tainted" in pandaLog.keys():
            # print(pandaLog["string_tainted"])
            if "instr_str" in pandaLog["string_tainted"].keys():
                disasDict["instr_str"] = pandaLog["string_tainted"]["instr_str"]
            else:
                disasDict["instr_str"] = ""
            if "instr_str" in pandaLog["string_tainted"].keys():
                disasDict["disas_str"] = pandaLog["string_tainted"]["disas_str"]
            else:
                disasDict["disas_str"] = ""
            addr = pandaLog["string_tainted"]["pc"]
            addrDisasDict[addr] = disasDict
    
    return addrDisasDict
    

def get_panda_addr_disas(addrDisasDict, addr):
    if addr in addrDisasDict.keys():
        return addrDisasDict[addr]["instr_str"], addrDisasDict[addr]["disas_str"]
    else:
        return "", ""

def remove_dict_key_list(d, key_list):
    r = dict(d)
    for key in key_list:
        del r[key]
    return r

def assication_2(decafPath, pandaPath, mdumpPath, resultFilePath):
    """
    以decaf污点分析的结果为主体，生成最终的关联分析结果
    """
    resultList = list()
    resultFile = open(resultFilePath, "w")
    decafFile = open(decafPath, "r")
    decafLogs = json.load(decafFile)
    pandaFile = codecs.open(pandaPath, "r", encoding="utf-8", errors='ignore')
    pandaLogs = json.load(pandaFile)
    mdumpFile = open(mdumpPath, "r")
    mdumpLogs = json.load(mdumpFile)
    
    
    # 处理common
    common = dict()
    common["os"] = pandaLogs[0]["os"]
    common["bits"] = pandaLogs[0]["bits"]
    common["proc_name"] =  pandaLogs[0]["proc_name"]
    dllDict = findDllDict(mdumpPath, common["proc_name"])
    common["exe_path"] = get_exe_path(dllDict, common["proc_name"])
    # 处理生成log
    associationLog = dict()
    decaf = dict()
    panda = dict()
    mdump = dict()
    
    addrDisasDict = findAddrDisasDict(pandaLogs)
    # print(addrDisasDict)
    for decafLog in decafLogs:
        associationLog.clear()
        decaf.clear()
        panda.clear()
        mdump.clear()
        associationLog["taint_period"] = decafLog["taint_period"]
        associationLog["common"] = common
        if associationLog["taint_period"] == "taint_source":
            # print(associationLog["taint_period"])
            decaf["taint_type"] = decafLog["taint_type"]
            decaf["taint_source"] = decafLog["taint_source"]
            panda["tainted_bytes"] , panda["tainted_string"]= get_panda_taint(pandaLogs)
            
        if associationLog["taint_period"] == "taint_propagation":
            # print(associationLog["taint_period"])
            decaf.update(decafLog["func"])
            decaf.pop("type")
            panda["instr_str"], panda["disas_str"] = get_panda_addr_disas(addrDisasDict, decaf["EIP"])
            for mdumpLog in mdumpLogs:
                # print(int(mdumpLog["EIP"][2:], base=16))
                if int(mdumpLog["EIP"], base=10) == decaf["EIP"]:
                    mdump = copy.deepcopy(mdumpLog)
                    remove_key_list = ["os", "bits", "analyzer", "timestamp", "EIP"]
                    mdump = remove_dict_key_list(mdump, remove_key_list)
                    break
        
        if associationLog["taint_period"] == "taint_leak":
            # print(associationLog["taint_period"])
            decaf.update(decafLog["func"])
            decaf.pop("type")
        
        associationLog["decaf"] = decaf
        associationLog["panda"] = panda
        associationLog["memdump"] = mdump
        # print(associationLog)
        resultList.append(copy.deepcopy(associationLog))
        
    json.dump(resultList, resultFile, sort_keys=False, indent=4, separators=(',', ':'))
    # print(len(resultList))
    resultFile.close()
    decafFile.close()
    pandaFile.close()
    mdumpFile.close()
    

def main(args):
    assert(os.path.exists(args.decaf) == True)
    assert(os.path.exists(args.panda) == True)
    if args.step == 1:
        assication_1(args.decaf, args.panda, args.generate)
    elif args.step == 2:
        assert(os.path.exists(args.mdump) == True)
        assication_2(args.decaf, args.panda, args.mdump, args.generate)
    else:
        print("Error: -s/--step must be 1 or 2")


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="association analyse")
    argparser.add_argument("-s", "--step", type=int, required=True)
    argparser.add_argument("-p", "--panda", type=str, required=True)
    argparser.add_argument("-d", "--decaf", type=str, required=True)
    argparser.add_argument("-g", "--generate", type=str)
    argparser.add_argument("-m", "--mdump", type=str)
    args = argparser.parse_args()
    # print(args)
    main(args)
    
    # assication_1("decaf.json", "panda.json", "EIP.csv")
    # dllDict = findDllDict("pyrebox.json","httpd.exe")
    # print(get_exe_path(dllDict, "httpd.exe"))
#    assication_2("decaf.json", "panda.json", "memdump.json", "association.json")

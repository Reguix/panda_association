#define __STDC_FORMAT_MACROS

#include <json/json.h>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>
#include <cassert>
#include <cstring>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

extern "C" {
#include <time.h>
#include "panda/rr/rr_log.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "stringsearch/stringsearch.h"
#include "tainted_net/tainted_net.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}
#define MAX_STR_LEN 512
Json::Value root;
char json_log_file[MAX_STR_LEN] = {0};
csh cs_handle_32;
csh cs_handle_64;


static inline bool pid_ok(int pid) {
    if (pid < 4) {
        return false;
    }
    return true;
}

static inline bool check_proc(OsiProc *proc) {
    if (!proc) return false;
    if (pid_ok(proc->pid)) {
        int l = strlen(proc->name);
        for (int i=0; i<l; i++) 
            if (!isprint(proc->name[i])) 
                return false;
    }
    if (strlen(proc->name) < 2) return false;
    return true;
}


inline void gen_one_log(CPUState *env, uint64_t curr_instr, char* log_key, Json::Value& log_value) {
    Json::Value one_log;
    uint64_t max_instr = replay_get_total_num_instructions();

    one_log["os"] = panda_os_family;
    one_log["bits"] = static_cast<unsigned>(panda_os_bits);

    OsiProc *proc = get_current_process(env);
    if (check_proc(proc)) {
        one_log["pid"] = static_cast<unsigned>(proc->pid);
        one_log["proc_name"] = proc->name;
    }
    one_log["ppid"] = static_cast<unsigned>(proc->ppid);
    one_log["cr3"] = static_cast<unsigned>(proc->asid);
    if(proc->exe_path != NULL)
        one_log["exe_path"] = (proc->exe_path) + 2;
    one_log["timestamp"] = static_cast<unsigned>(time(NULL));
    one_log["curr_instr"] = static_cast<unsigned>(curr_instr);
    one_log["replay_percent"] = (static_cast<float>(curr_instr) / static_cast<float>(max_instr) * 100);
    one_log[log_key] = log_value;
    root.append(one_log);
}

bool disas_block(CPUState* cpu, target_ulong pc, unsigned char *buf, int size, char *disas_str) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // note which build was used, as it is useful in analyzing the results
#ifdef USE_STACK_HEURISTIC
    printf("using USE_STACK_HEURISTIC build\n");
#else
    printf("using standard build\n");
#endif

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif


    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) {
        printf("Couldn't read TB memory!\n"); 
        return false;
    }

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_CS64_MASK) ? cs_handle_64 : cs_handle_32;
#if !defined(TARGET_X86_64)
    if ((env->hflags & HF_CS32_MASK) == 0) {
        cs_option(handle, CS_OPT_MODE, CS_MODE_16);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_32);
    }
#endif
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }

#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif

    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);
    if (count <= 0) return false;
    size_t j;
    for (j = 0; j < count; ++j) {
			sprintf(disas_str + strlen(disas_str), "0x%lX:    %s        %s;", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}
    cs_free(insn, count);
    cs_close(&handle);
    return true;
}

inline void str_to_hex(unsigned char *s, char *d) {
    size_t i;
    for(i = 0; i < strlen((const char *)s); ++i) {
        sprintf(d + strlen(d), "0x%02X ", s[i]);
    }
}

void on_string_tainted(CPUState *env, target_ulong pc, target_ulong addr, 
                        uint8_t *buf, uint32_t matched_string_length, uint64_t curr_instr) {
    char log_key[MAX_STR_LEN] = "string_tainted";
    char matched_string[MAX_STR_LEN] = {0};
    memcpy(matched_string, buf, matched_string_length);

    Json::Value log_value;
    log_value["pc"] = static_cast<unsigned>(pc);
    char disas_str[MAX_STR_LEN] = {0};
    unsigned char instr_buf[MAX_STR_LEN] = {0};
    if(disas_block(env, pc, instr_buf, panda_os_bits/8, disas_str)) {
        
        char instr_str[MAX_STR_LEN] = {0};
        str_to_hex(instr_buf, instr_str);
        log_value["instr_str"] = instr_str;
        log_value["disas_str"] = disas_str;
    }

    log_value["addr"] = static_cast<unsigned>(addr);
    log_value["tainted_string"] = matched_string;
    log_value["tainted_bytes"] = matched_string_length;
    gen_one_log(env, curr_instr, log_key, log_value);
}

inline std::string get_label_string(uint32_t *taint_labels, uint32_t numLabels) {
    std::string label_string = "";
    for(unsigned i = 0; i < numLabels; ++i) {
        label_string += std::to_string(taint_labels[i]) + " ";
    }
    return label_string;
}

void on_tainted_out_net(CPUState *env, uint64_t curAddr, uint8_t buf, 
                        uint32_t *taint_labels, uint32_t numLabels, uint64_t curr_instr) {
    char log_key[16] = "tainted_out_net";
    char tainted_ram[MAX_STR_LEN] = {0};
    memcpy(tainted_ram, &buf, sizeof(buf));
    Json::Value log_value;
    log_value["tainted_ram"] = tainted_ram;
    log_value["addr"] = static_cast<unsigned>(curAddr);
    log_value["num_labels"] = static_cast<unsigned>(numLabels);
    log_value["label_string"] = get_label_string(taint_labels, numLabels);
    gen_one_log(env, curr_instr, log_key, log_value);
}


bool init_plugin(void *self) {    

    panda_require("osi");
    assert(init_osi_api());
    
    panda_arg_list *args = panda_get_args("jsonlog");
    const char *prefix = panda_parse_string_opt(args, "name", "jsonlog", "prefix of json log filename");
    if (strlen(prefix) > 0) {
        sprintf(json_log_file, "%s.json", prefix);
        printf ("json log file [%s]\n", json_log_file);
    }
    panda_free_args(args);

    PPP_REG_CB("stringsearch", on_string_tainted, on_string_tainted);
    PPP_REG_CB("tainted_net", on_tainted_out_net, on_tainted_out_net);

    return true;
}

void uninit_plugin(void *self) {

    printf("jsonlog: unloading jsonlog plugin.\n");
    Json::StyledWriter sw;
    std::ofstream os;
    os.open(json_log_file);
    os << sw.write(root);
    os.close();
    printf("jsonlog: log in %s\n", json_log_file);
}


#ifndef __TAINTED_NET_H_
#define __TAINTED_NET_H_



typedef void (*on_tainted_out_net_t)(CPUState *env, uint64_t curAddr, uint8_t buf, 
                        uint32_t *taint_labels, uint32_t numLabels, uint64_t curr_instr);





#endif

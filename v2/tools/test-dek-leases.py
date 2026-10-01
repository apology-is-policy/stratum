#!/usr/bin/env python3
"""Compile actual ctl lease functions; FS boundary injects proof/evict failures."""
from pathlib import Path
import subprocess, tempfile
root=Path(__file__).resolve().parent.parent
s=(root/'src/ctl/synfs.c').read_text()
def function(signature):
 start=s.index(signature); a=s.index('{',start); n=1; end=a+1
 while n:
  if s[end]=='{': n+=1
  elif s[end]=='}': n-=1
  end+=1
 return s[start:end]
body='\n'.join(function(x) for x in ('static stm_status ctl_dek_install(', 'static bool ctl_dek_other_lease(', 'static stm_status ctl_dek_evict('))
a=s.index('    pthread_mutex_lock(&ctl->dek_mu);',s.index('void stm_ctl_conn_destroy('));b=s.index('    pthread_mutex_unlock(&ctl->dek_mu);',a)+len('    pthread_mutex_unlock(&ctl->dek_mu);')
body+='\nstatic void drop(stm_ctl_conn *cn) { stm_ctl *ctl=cn->ctl;\n'+s[a:b]+'\n}\n'
shim=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <pthread.h>
typedef int stm_status;
enum { STM_OK, STM_EINVAL, STM_EACCES, STM_ENOSPC };
#define STM_CTL_DEK_LEASE_MAX 64
typedef struct stm_ctl_conn stm_ctl_conn;
typedef struct {bool active; uint64_t dataset_id; const stm_ctl_conn *owner;} ctl_dek_lease;
typedef struct {bool corvus_socket_set; const char *corvus_socket_path;
 uint32_t corvus_connect_timeout_ms,corvus_io_timeout_ms,corvus_n_retries;
 pthread_mutex_t dek_mu; void *fs; ctl_dek_lease dek_leases[64];} stm_ctl;
struct stm_ctl_conn {stm_ctl *ctl;};
typedef struct {const char *socket_path; const uint8_t *session_token;
 uint32_t connect_timeout_ms,io_timeout_ms,n_retries;} stm_corvus_mount_cfg;
static int proofs, evictions; static stm_status proof_result, eviction_result;
static stm_status stm_fs_install_dek(void *fs,uint64_t ds,const stm_corvus_mount_cfg *cfg) {
 (void)fs;(void)ds; assert(cfg->session_token); proofs++;return proof_result;
}
static stm_status stm_fs_evict_dek(void *fs,uint64_t ds) {
 (void)fs;(void)ds;evictions++;return eviction_result;
}
'''
tests=r'''
int main(void) {
 stm_ctl c={.corvus_socket_set=true,.fs=(void*)1,.dek_mu=PTHREAD_MUTEX_INITIALIZER};
 stm_ctl_conn a={&c},b={&c},foreign={&c}; uint8_t tok=1;
 assert(ctl_dek_install(&a,2,&tok)==STM_OK && proofs==1);
 assert(ctl_dek_install(&a,2,&tok)==STM_OK && proofs==1);
 proof_result=STM_EACCES;
 assert(ctl_dek_install(&b,2,&tok)==STM_EACCES && proofs==2);
 assert(ctl_dek_evict(&b,2)==STM_EACCES && evictions==0);
 proof_result=STM_OK;
 assert(ctl_dek_install(&b,2,&tok)==STM_OK && proofs==3);
 assert(ctl_dek_evict(&foreign,2)==STM_EACCES);
 assert(ctl_dek_evict(&a,2)==STM_OK && evictions==0);
 assert(ctl_dek_evict(&b,2)==STM_OK && evictions==1);
 assert(ctl_dek_install(&a,2,&tok)==STM_OK);
 assert(ctl_dek_install(&b,2,&tok)==STM_OK);
 drop(&a); assert(evictions==1);
 eviction_result=STM_EINVAL;
 assert(ctl_dek_evict(&b,2)==STM_EINVAL && evictions==2);
 eviction_result=STM_OK;
 drop(&b); assert(evictions==3);
 assert(ctl_dek_evict(&foreign,2)==STM_OK && evictions==3);
 stm_ctl_conn owners[65];
 for(int i=0;i<65;i++)owners[i].ctl=&c;
 for(int i=0;i<64;i++)assert(ctl_dek_install(&owners[i],2,&tok)==STM_OK);
 int before=proofs;
 assert(ctl_dek_install(&owners[64],2,&tok)==STM_ENOSPC && proofs==before);
 for(int i=0;i<63;i++){drop(&owners[i]);assert(evictions==3);}
 drop(&owners[63]);assert(evictions==4);
 assert(ctl_dek_install(&a,2,&tok)==STM_OK);
 drop(&a);assert(evictions==5);
 pthread_mutex_destroy(&c.dek_mu);
}
'''
mutants={
 'foreign-idempotence':('c->dek_leases[i].dataset_id == dataset_id &&\n            c->dek_leases[i].owner == cn','c->dek_leases[i].dataset_id == dataset_id'),
 'evict-survivor':('ctl_dek_other_lease(c, i) ? STM_OK :','false ? STM_OK :'),
 'drop-survivor':('ctl->fs && !ctl_dek_other_lease(ctl, i)','ctl->fs'),
 'skip-new-proof':('stm_status rc = stm_fs_install_dek(c->fs, dataset_id, &cfg);','stm_status rc = (void)cfg, STM_OK;'),
}
# The proof-skipping mutant keeps the call syntactically available but unreachable.
mutants['skip-new-proof']=(mutants['skip-new-proof'][0], 'stm_status rc = false ? stm_fs_install_dek(c->fs, dataset_id, &cfg) : STM_OK;')
with tempfile.TemporaryDirectory(prefix='stm-dek-leases-') as tmp:
 p=Path(tmp)
 for name,m in [('clean',None),*mutants.items()]:
  code=body
  if m:
   assert code.count(m[0])==1,name
   code=code.replace(*m)
  (p/'test.c').write_text(shim+code+tests)
  subprocess.run(['cc','-std=c17','-pthread','-Wall','-Wextra',str(p/'test.c'),'-o',str(p/'test')],check=True)
  r=subprocess.run([str(p/'test')],capture_output=True,text=True)
  if m: assert r.returncode!=0 and 'Assertion' in r.stderr,(name,r.stderr)
  else: r.check_returncode()
  print(name+(': intended assertion failure' if m else ': PASS'),flush=True)

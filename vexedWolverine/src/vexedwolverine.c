/* Benign expert crackme. No networking, persistence, injection, RWX pages,
 * process spawning, privilege changes, credential access or file writes.
 * The bytecode is interpreted data, never native executable payload.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/proc.h>
#endif
#endif
#include "crypto.h"
#if defined(__GNUC__)
#if defined(__APPLE__)
#define VW_SECTION __attribute__((section("__DATA,__vwdata"),used))
#else
#define VW_SECTION __attribute__((section(".vwdata"),used))
#endif
#define VW_NOINLINE __attribute__((noinline))
#else
#define VW_SECTION
#define VW_NOINLINE
#endif
#include "generated.h"

static const volatile char bait_a[]="VW{RAW_STRINGS_ARE_NOT_A_SOLUTION}";
static const volatile char bait_b[]="VW{THE_FAST_PATH_IS_A_DECOY}";
static const volatile char bait_c[]="c2.vexedwolverine-demo.invalid";
static const volatile char bait_d[]="already_unlocked=true; endpoint=127.0.0.1:0";
static _Thread_local uint32_t lane_cookie;
typedef struct {
    uint8_t root[32],seed[32];uint8_t *container,*strings;
    const uint8_t *map_a,*map_b,*nonce_a,*nonce_b,*nonce_s,*nonce_f,*digest_f;
    uint8_t *prog_a,*prog_b,*flag;uint32_t na,nb,ns,nf,offsets[10];
    const char *ticket;uint32_t host_cookie;int result,lab_mode;
} Work;

static VW_NOINLINE int equal_bytes(const uint8_t *a,const uint8_t *b,size_t n) {
    uint32_t difference=0;size_t i;for(i=0;i<n;i++)difference|=a[i]^b[i];return difference==0;
}
static const char *message(Work *w,unsigned index) {
    uint32_t offset;
    if(index>=10||!w->strings)return "";
    offset=w->offsets[index];
    if(offset>=w->ns||!memchr(w->strings+offset,0,w->ns-offset))return "";
    return (const char*)w->strings+offset;
}
static uint64_t wall_ms(void) {
#if defined(_WIN32)
    return GetTickCount64();
#else
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0)return 0;
    return (uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
#endif
}
#if defined(_WIN32)
static VW_NOINLINE FARPROC name_from_hash(uint32_t wanted) {
    HMODULE mod=GetModuleHandleA("kernel32.dll");uint8_t *base=(uint8_t*)mod;
    IMAGE_DOS_HEADER *dos;IMAGE_NT_HEADERS *nt;IMAGE_EXPORT_DIRECTORY *ex;
    DWORD *names;DWORD i,j;uint32_t hash;const char *name;
    if(!mod)return NULL;
    dos=(IMAGE_DOS_HEADER*)base;nt=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    if(!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)return NULL;
    ex=(IMAGE_EXPORT_DIRECTORY*)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names=(DWORD*)(base+ex->AddressOfNames);
    for(i=0;i<ex->NumberOfNames;i++) {
        name=(const char*)base+names[i];hash=0;
        for(j=0;name[j];j++)hash=v_ror(hash,13)+(uint8_t)name[j];
        if(hash==wanted)return GetProcAddress(mod,name); /* resolves forwarders */
    }
    return NULL;
}
#endif
static VW_NOINLINE int debugger_observed(Work *w) {
#if defined(_WIN32)
    typedef BOOL (WINAPI *Query)(void);
    FARPROC raw=name_from_hash(VW_DEBUG_API_HASH);
    Query query=NULL;
    _Static_assert(sizeof query==sizeof raw,"function pointer size mismatch");
    memcpy(&query,&raw,sizeof query);
    (void)w;return query?query()!=0:0;
#elif defined(__APPLE__)
    int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,0};struct kinfo_proc info;
    size_t size=sizeof info;(void)w;memset(&info,0,sizeof info);mib[3]=getpid();
    if(sysctl(mib,4,&info,&size,NULL,0)!=0)return 0;
    return (info.kp_proc.p_flag&P_TRACED)!=0;
#else
    FILE *file;char line[256];size_t prefix;unsigned long tracer=0;
    file=fopen(message(w,7),"r");if(!file)return 0;prefix=strlen(message(w,8));
    while(fgets(line,sizeof line,file))if(prefix&&strncmp(line,message(w,8),prefix)==0){tracer=strtoul(line+prefix,NULL,10);break;}
    fclose(file);return tracer!=0;
#endif
}
static VW_NOINLINE void assemble_root(uint8_t out[32]) {
    unsigned i,n;uint8_t b;
    for(i=0;i<32;i++){n=(i%7)+1;b=q_b[(i*13)&31];out[i]=(uint8_t)(((uint32_t)b<<n)|(b>>(8-n)))^q_a[(i*7)&31]^(uint8_t)(i*29+0x63);}
}
static VW_NOINLINE int unpack_container(Work *w) {
    uint8_t digest[32],key[32];unsigned i;uint64_t total;uint8_t *p;
    v_hash(q_blob,sizeof q_blob,digest);if(!equal_bytes(digest,q_digest,32))return 0;
    w->container=(uint8_t*)malloc(sizeof q_blob);if(!w->container)return 0;
    /* Read the intended data section directly rather than letting the compiler
       emit another whole-container literal for an optimized memcpy. */
    for(i=0;i<sizeof q_blob;i++)w->container[i]=((const volatile uint8_t*)q_blob)[i];
    v_stream(w->root,q_nonce,w->container,sizeof q_blob);
    p=w->container;
    if(sizeof q_blob<656||v_ld(p)!=0x414c5756||v_ld(p+4)!=0x00313042)return 0;
    w->na=v_ld(p+8);w->nb=v_ld(p+12);w->ns=v_ld(p+16);w->nf=v_ld(p+20);
    total=656ull+w->na+w->nb+w->ns+w->nf;
    if(total!=sizeof q_blob||w->na%4||w->nb%12||w->nf<4||w->nf>256||!w->ns)return 0;
    w->nonce_a=p+24;w->nonce_b=p+36;w->nonce_s=p+48;w->nonce_f=p+60;
    w->map_a=p+72;w->map_b=p+328;
    for(i=0;i<10;i++)w->offsets[i]=v_ld(p+584+i*4);
    w->digest_f=p+624;w->prog_a=p+656;w->prog_b=w->prog_a+w->na;
    w->strings=w->prog_b+w->nb;w->flag=w->strings+w->ns;
    v_derive(w->root,'s',key);v_stream(key,w->nonce_s,w->strings,w->ns);
    v_zero(key,sizeof key);return 1;
}
static VW_NOINLINE int stack_lane(Work *w) {
    uint8_t key[32],stack[128];unsigned sp=0,pc,kind,arg,a,b,n;
    uint32_t written=0;uint8_t *p;
    v_derive(w->root,'a',key);v_stream(key,w->nonce_a,w->prog_a,w->na);v_zero(key,32);
    for(pc=0;pc<w->na/4;pc++) {
        p=w->prog_a+pc*4;kind=w->map_a[p[0]];
        arg=p[1]^w->root[pc&31]^(uint8_t)(pc*17);
        if(p[3]!=(uint8_t)(p[0]^arg^p[2]^pc))return 0;
        /* Stack VM and register VM intentionally have different formats. */
        switch(kind) {
        case 0:if(sp>=128)return 0;stack[sp++]=(uint8_t)arg;break;
        case 1:if(sp<2)return 0;b=stack[--sp];stack[sp-1]^=(uint8_t)b;break;
        case 2:if(sp<2)return 0;b=stack[--sp];stack[sp-1]=(uint8_t)(stack[sp-1]+b);break;
        case 3:if(!sp)return 0;n=arg&7;a=stack[sp-1];stack[sp-1]=(uint8_t)((a<<n)|(a>>((8-n)&7)));break;
        case 4:if(!sp||arg>=32)return 0;w->seed[arg]=stack[--sp];written|=1u<<arg;break;
        case 5:if(!sp||sp>=128)return 0;a=stack[sp-1];stack[sp++]=(uint8_t)a;break;
        case 6:if(sp<2)return 0;a=stack[sp-1];stack[sp-1]=stack[sp-2];stack[sp-2]=(uint8_t)a;break;
        case 7:if(!sp)return 0;sp--;break;
        case 8:break;
        case 9:v_zero(stack,sizeof stack);return written==0xffffffffu&&sp==0&&pc+1==w->na/4;
        default:return 0;
        }
    }
    v_zero(stack,sizeof stack);return 0;
}
static VW_NOINLINE int register_lane(Work *w) {
    uint32_t r[16]={0},difference=0,imm,tag,kw;unsigned pc,kind,a,b,count=0;uint8_t *p;
    uint32_t cookie=w->host_cookie^0x3b79af51u;
    if(lane_cookie!=cookie)return 0;
    v_stream(w->seed,w->nonce_b,w->prog_b,w->nb);
    for(pc=0;pc<w->nb/12;pc++) {
        p=w->prog_b+pc*12;kw=v_ld(w->seed+(pc&7)*4);
        tag=v_fnv(p,8,2166136261u^pc^kw);
        if(tag!=v_ld(p+8))return 0;
        kind=w->map_b[p[0]];a=p[1]^w->seed[pc&31];b=p[2]^w->seed[(pc+11)&31];
        imm=v_ror(v_ld(p+4),(pc%31)+1)^kw;
        if(a>=16||b>=16)return 0;
        switch(kind) {
        case 0:if(imm>28)return 0;r[a]=v_ld((const uint8_t*)w->ticket+imm);break;
        case 1:r[a]+=r[b];break;
        case 2:r[a]^=r[b];break;
        case 3:r[a]+=imm;break;
        case 4:r[a]^=imm;break;
        case 5:r[a]=v_rol(r[a],imm);break;
        case 6:r[a]=v_ror(r[a],imm);break;
        case 7:tag=r[a];r[a]=r[b];r[b]=tag;break;
        case 8:if(!(imm&1))return 0;r[a]*=imm;break;
        case 9:if(!(imm&31))return 0;r[a]^=r[a]>>(imm&31);break;
        case 10:difference|=r[a]^imm;count++;break;
        case 11:r[a]=imm;break;
        case 12:/* Junk dispatch with a nontrivial but irrelevant accumulator. */cookie=v_rol(cookie+tag,7)^pc;break;
        case 13:v_zero(r,sizeof r);lane_cookie=cookie;return difference==0&&count==8&&pc+1==w->nb/12;
        default:return 0;
        }
    }
    v_zero(r,sizeof r);return 0;
}
static VW_NOINLINE int reveal_lane(Work *w) {
    uint8_t key[32],digest[32],tag[2]={'/','f'};VHash hash;
    v_hash_init(&hash);v_hash_add(&hash,w->ticket,32);v_hash_add(&hash,w->seed,32);v_hash_add(&hash,tag,2);v_hash_end(&hash,key);
    v_stream(key,w->nonce_f,w->flag,w->nf);v_zero(key,32);v_hash(w->flag,w->nf,digest);
    if(!equal_bytes(digest,w->digest_f,32)){puts(message(w,5));return 0;}
    if(w->flag[0]!='V'||w->flag[1]!='W'||w->flag[2]!='{'||w->flag[w->nf-1]!='}')return 0;
    fwrite(w->flag,1,w->nf,stdout);putchar('\n');return 1;
}
static VW_NOINLINE void execute_worker(Work *w) {
    /* Flattened state machine with encoded transitions and an opaque predicate.
     * No native code decryption/execution: both lanes are ordinary interpreters.
     */
    uint32_t salt=w->host_cookie^0x9a6173bdu,state=0x1483u^salt;
    uint64_t start=wall_ms();volatile uint32_t opaque=w->host_cookie;int done=0;
    lane_cookie=w->host_cookie^0x3b79af51u;
    while(!done) {
        switch(state^salt) {
        case 0x1483:
            if((opaque*(opaque+1u))&1u)state=0x7731u^salt;
            else state=0x8267u^salt;
            break;
        case 0x8267:
            if(!w->lab_mode&&debugger_observed(w)){puts(message(w,3));state=0x7731u^salt;}
            else state=0x2319u^salt;
            break;
        case 0x2319:state=(stack_lane(w)?0xab51u:0x7731u)^salt;break;
        case 0xab51:
            {
                int valid=register_lane(w);
#ifdef VW_INSTRUCTOR_FORCE_VALID
                valid=1; /* Instructor-only test: patching validation is insufficient. */
#endif
                state=(valid?0x517du:0x7731u)^salt;
            }
            break;
        case 0x517d:
            if(!w->lab_mode&&wall_ms()-start>90000u){puts(message(w,4));state=0x7731u^salt;}
            else state=0xc913u^salt;
            break;
        case 0xc913:w->result=reveal_lane(w);state=0xed07u^salt;break;
        case 0x7731:puts(message(w,2));w->result=0;state=0xed07u^salt;break;
        case 0xed07:done=1;break;
        default:w->result=0;done=1;break;
        }
    }
    lane_cookie=0;
}
#if defined(_WIN32)
static DWORD WINAPI worker_start(LPVOID p){execute_worker((Work*)p);return 0;}
#else
static void *worker_start(void *p){execute_worker((Work*)p);return NULL;}
#endif
int main(int argc,char **argv) {
    Work work;size_t i;int ok=0;const char *mode;memset(&work,0,sizeof work);
    /* Reading volatile decoys keeps bait in the release without activating it. */
    work.host_cookie=(uint32_t)(wall_ms()^bait_a[3]^bait_b[3]^bait_c[3]^bait_d[3]);
    assemble_root(work.root);
    if(!unpack_container(&work)){fputs("Container integrity mismatch.\n",stderr);goto cleanup;}
    puts(message(&work,0));
    if(argc!=2||strlen(argv[1])!=32){puts(message(&work,1));goto cleanup;}
    for(i=0;i<32;i++)if(!strchr("ABCDEFGHJKLMNPQRSTUVWXYZ23456789",argv[1][i])){puts(message(&work,2));goto cleanup;}
    work.ticket=argv[1];mode=getenv(message(&work,9));work.lab_mode=mode&&strcmp(mode,"1")==0;
#if defined(_WIN32)
    {
        HANDLE thread=CreateThread(NULL,0,worker_start,&work,0,NULL);
        if(!thread)goto cleanup;
        WaitForSingleObject(thread,INFINITE);CloseHandle(thread);
    }
#else
    {
        pthread_t thread;if(pthread_create(&thread,NULL,worker_start,&work)!=0)goto cleanup;
        if(pthread_join(thread,NULL)!=0){/* Fatal thread-join failure: process exit reclaims memory. */return 1;}
    }
#endif
    ok=work.result;
cleanup:
    if(work.container){v_zero(work.container,sizeof q_blob);free(work.container);}
    v_zero(&work,sizeof work);return ok?0:1;
}

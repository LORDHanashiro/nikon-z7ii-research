// HOST-ONLY synthetic transport prototype. Not a Nikon format or camera interface.
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using Clock=std::chrono::steady_clock;
static uint64_t ns(Clock::duration d) { return std::chrono::duration_cast<std::chrono::nanoseconds>(d).count(); }
static uint32_t crc(const uint8_t* p,size_t n) {
    static const auto table=[] { std::array<uint32_t,256> t{}; for(uint32_t i=0;i<256;i++) {
        uint32_t c=i; for(int k=0;k<8;k++) c=(c>>1)^((c&1)?0xedb88320u:0); t[i]=c;
    } return t; }();
    uint32_t c=~0u; for(size_t i=0;i<n;i++) c=table[(c^p[i])&255]^(c>>8); return ~c;
}
static void le(uint8_t* p,uint64_t v,int n) { for(int i=0;i<n;i++) p[i]=uint8_t(v>>(8*i)); }
struct Config {
    uint32_t w=1920,h=1080,frames=12,slots=3,delay=0,short_write=0;
    int64_t fail_after=-1;
    bool quantize=false, nonwaiting=false, test_hold_writer=false;
    std::string output;
};
struct Output {
    int fd=-1; uint64_t bytes=0,calls=0; const Config& c;
    explicit Output(const Config& x):c(x) {
        fd=open(c.output.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
        if(fd<0) throw std::runtime_error("exclusive output open failed");
    }
    ~Output() { if(fd>=0) close(fd); }
    void write_all(const uint8_t* p,size_t n) {
        while(n) {
            size_t chunk=c.short_write?std::min(n,size_t(c.short_write)):n;
            if(c.fail_after>=0) {
                if(bytes>=uint64_t(c.fail_after)) throw std::runtime_error("injected HOST write failure");
                chunk=std::min(chunk,size_t(uint64_t(c.fail_after)-bytes));
            }
            ssize_t got=write(fd,p,chunk); calls++;
            if(got<0 && errno==EINTR) continue;
            if(got<=0) throw std::runtime_error("host write failed");
            p+=got; n-=size_t(got); bytes+=uint64_t(got);
        }
    }
};
enum class State { FREE,FILLING,READY,WRITING };
struct Slot { std::vector<uint8_t> data; uint32_t sequence=0,checksum=0; State state=State::FREE; };
static void fill(Slot& s,const Config& c,size_t stride) {
    std::fill(s.data.begin(),s.data.end(),0); // Canonical zero row padding.
    for(uint32_t y=0;y<c.h;y++) for(uint32_t x=0;x<c.w;x+=2) {
        uint32_t f=s.sequence;
        uint64_t u=(17*f+3*(x/2)+5*y+101)&1023;
        uint64_t y0=(19*f+x+7*y)&1023;
        uint64_t v=(23*f+11*(x/2)+13*y+503)&1023;
        uint64_t y1=(19*f+x+1+7*y)&1023;
        if(c.quantize) { u&=~3ull;y0&=~3ull;v&=~3ull;y1&=~3ull; }
        uint64_t word=u|(y0<<10)|(v<<20)|(y1<<30);
        le(s.data.data()+stride*y+size_t(x/2)*5,word,5);
    }
    s.checksum=crc(s.data.data(),s.data.size());
}
int main(int argc,char** argv) {
    try {
        Config c;
        for(int i=1;i<argc;i++) {
            std::string a=argv[i];
            if(a=="--quantize-to-8") { c.quantize=true;continue; }
            if(a=="--no-wait-for-slot") { c.nonwaiting=true;continue; }
            if(a=="--test-hold-writer-until-source-done") { c.test_hold_writer=true;continue; }
            if(i+1==argc) throw std::runtime_error("missing option value");
            std::string value=argv[++i];
            if(a=="--output") { c.output=value;continue; }
            size_t used=0;uint64_t n=std::stoull(value,&used);
            if(used!=value.size() || n>std::numeric_limits<uint32_t>::max()) throw std::runtime_error("invalid bounded integer");
            if(a=="--width") c.w=n;
            else if(a=="--height") c.h=n;
            else if(a=="--frames") c.frames=n;
            else if(a=="--slots") c.slots=n;
            else if(a=="--writer-delay-ms") c.delay=n;
            else if(a=="--short-write") c.short_write=n;
            else if(a=="--fail-after") c.fail_after=n;
            else throw std::runtime_error("unknown option");
        }
        if(c.output.empty() || !c.w || c.w%2 || c.w>4096 || !c.h || c.h>2160 ||
           !c.frames || c.frames>256 || !c.slots || c.slots>8 || c.delay>100)
            throw std::runtime_error("configuration outside prototype safety bounds");
        if(c.test_hold_writer && !c.nonwaiting)
            throw std::runtime_error("HOST test barrier requires no-wait admission mode");
        size_t stride=((size_t(c.w)*5/2+63)/64)*64, framebytes=stride*c.h;
        if(framebytes*c.frames+64+size_t(c.frames)*48>512ull*1024*1024 || framebytes*c.slots>256ull*1024*1024)
            throw std::runtime_error("file or memory cap exceeded");
        Output out(c);auto start=Clock::now();
        std::array<uint8_t,64> header{};std::memcpy(header.data(),"N10PROT",7);
        le(header.data()+8,1,4);le(header.data()+12,c.w,4);le(header.data()+16,c.h,4);
        le(header.data()+20,stride,4);le(header.data()+24,30000,4);le(header.data()+28,1001,4);
        le(header.data()+32,1,4);le(header.data()+36,1,4); // Self-defined packing / SYNTHETIC source.
        le(header.data()+40,framebytes,8);le(header.data()+48,c.frames,8);
        le(header.data()+60,crc(header.data(),60),4);out.write_all(header.data(),header.size());
        std::vector<Slot> slots(c.slots);std::deque<size_t> free,ready;
        for(size_t i=0;i<slots.size();i++) { slots[i].data.resize(framebytes);free.push_back(i); }
        std::mutex m;std::condition_variable cv;bool aborted=false,producer_done=false;
        std::string error;uint64_t waits=0,wait_ns=0,produced=0,written=0,peak=0,rejected=0;
        auto fail=[&](const std::string& message) { std::lock_guard<std::mutex> l(m);aborted=true;error=message;cv.notify_all(); };
        std::thread producer([&] {
            try {
                for(uint32_t f=0;f<c.frames;f++) {
                    size_t i;
                    {
                        std::unique_lock<std::mutex> l(m);auto before=Clock::now();
                        if(c.nonwaiting) {
                            if(aborted) break;
                            if(free.empty()) { rejected++;error="HOST source admission full";break; }
                        } else {
                            if(free.empty()) waits++;
                            cv.wait(l,[&]{return aborted || !free.empty();});wait_ns+=ns(Clock::now()-before);
                        }
                        if(aborted) break;
                        i=free.front();free.pop_front();
                        if(slots[i].state!=State::FREE) throw std::runtime_error("invalid FREE ownership");
                        slots[i].state=State::FILLING;slots[i].sequence=f;
                        peak=std::max(peak,uint64_t(c.slots-free.size()));
                    }
                    fill(slots[i],c,stride);
                    {
                        std::lock_guard<std::mutex> l(m);if(aborted) break;
                        if(slots[i].state!=State::FILLING) throw std::runtime_error("invalid FILLING ownership");
                        slots[i].state=State::READY;ready.push_back(i);produced++;cv.notify_all();
                    }
                }
                std::lock_guard<std::mutex> l(m);producer_done=true;cv.notify_all();
            } catch(const std::exception& e) { fail(e.what()); }
        });
        std::thread writer([&] {
            try {
                if(c.test_hold_writer) {
                    // Deterministic HOST-only test barrier. Not a device ready/IRQ event.
                    std::unique_lock<std::mutex> l(m);
                    cv.wait(l,[&]{return aborted || producer_done;});
                }
                for(;;) {
                    size_t i;
                    {
                        std::unique_lock<std::mutex> l(m);cv.wait(l,[&]{return aborted || !ready.empty() || producer_done;});
                        if(aborted || (ready.empty() && producer_done)) break;
                        i=ready.front();ready.pop_front();
                        if(slots[i].state!=State::READY) throw std::runtime_error("invalid READY ownership");
                        slots[i].state=State::WRITING;
                    }
                    if(c.delay) std::this_thread::sleep_for(std::chrono::milliseconds(c.delay));
                    auto& s=slots[i];std::array<uint8_t,32> fh{};std::memcpy(fh.data(),"FRM1",4);
                    le(fh.data()+4,s.sequence,4);le(fh.data()+8,uint64_t(s.sequence)*1000000000ull*1001/30000,8);
                    le(fh.data()+16,framebytes,8);le(fh.data()+24,s.checksum,4);le(fh.data()+28,crc(fh.data(),28),4);
                    std::array<uint8_t,16> foot{};std::memcpy(foot.data(),"END1",4);le(foot.data()+4,s.sequence,4);
                    le(foot.data()+8,s.checksum,4);le(foot.data()+12,crc(foot.data(),12),4);
                    out.write_all(fh.data(),fh.size());out.write_all(s.data.data(),s.data.size());out.write_all(foot.data(),foot.size());
                    {
                        std::lock_guard<std::mutex> l(m);if(s.state!=State::WRITING) throw std::runtime_error("invalid WRITING ownership");
                        s.state=State::FREE;free.push_back(i);written++;cv.notify_all();
                    }
                }
            } catch(const std::exception& e) { fail(e.what()); }
        });
        producer.join();writer.join();auto before_sync=Clock::now();
        bool synced=false;
        if(!aborted) { if(fsync(out.fd)!=0) { aborted=true;error="host fsync failed"; } else synced=true; }
        uint64_t sync_ns=ns(Clock::now()-before_sync),elapsed=ns(Clock::now()-start);
        bool complete=!aborted && produced==c.frames && written==c.frames && free.size()==c.slots;
        std::cout<<"{\"scope\":\"HOST-ONLY SYNTHETIC, no Nikon format or throughput claim\",\"complete\":"<<(complete?"true":"false")
                 <<",\"frames_produced\":"<<produced<<",\"frames_written\":"<<written<<",\"bytes\":"<<out.bytes
                 <<",\"row_stride\":"<<stride<<",\"slot_bytes\":"<<framebytes*c.slots<<",\"slots\":"<<c.slots
                 <<",\"peak_slots_in_use\":"<<peak<<",\"producer_waits\":"<<waits<<",\"producer_wait_ns\":"<<wait_ns
                 <<",\"no_wait_for_slot\":"<<(c.nonwaiting?"true":"false")<<",\"admission_rejections\":"<<rejected
                 <<",\"host_test_writer_barrier\":"<<(c.test_hold_writer?"true":"false")
                 <<",\"write_syscalls\":"<<out.calls<<",\"elapsed_ns\":"<<elapsed<<",\"fsync_ns\":"<<sync_ns
                 <<",\"host_fsync_completed\":"<<(synced?"true":"false")<<",\"error\":\""<<error<<"\"}\n";
        return complete?0:1;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 2; }
}

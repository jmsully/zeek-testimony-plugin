#include <threading/BasicThread.h>
#include <functional>

using namespace zeek::threading;

class TemporaryQueueWriter: BasicThread {
public:
    void SetTestimonySource(std::function<void()> testimony_queue_writer){
        _testimony_queue_writer = testimony_queue_writer;
    }

    void StartThread();
    void Stop();
protected:

    void Run() override;
    void OnWaitForStop() override;
private:
    std::function<void()> _testimony_queue_writer;
};
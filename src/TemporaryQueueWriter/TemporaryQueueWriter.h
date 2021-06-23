#include <zeek/threading/BasicThread.h>
#include <functional>

using namespace zeek::threading;

class TemporaryQueueWriter: BasicThread 
    {
public:

    void SetTestimonySource(std::function<void()> testimony_queue_writer){
        _testimony_queue_writer = testimony_queue_writer;
    }

    void SetStoppingProcess(std::function<void()> testimony_queue_stopper) {
        _testimony_queue_stopper = testimony_queue_stopper;
    }

    void OnSignalStop() override {
        _testimony_queue_stopper();
    }

    void StartThread();
protected:

    void Run() override;
    void OnWaitForStop() override;
private:
    std::function<void()> _testimony_queue_writer;
    std::function<void()> _testimony_queue_stopper;
    };
#include "TemporaryQueueWriter.h"

void TemporaryQueueWriter::Run() {
    _testimony_queue_writer();
}

void TemporaryQueueWriter::OnWaitForStop(){

}

void TemporaryQueueWriter::StartThread() {
    Start();
}
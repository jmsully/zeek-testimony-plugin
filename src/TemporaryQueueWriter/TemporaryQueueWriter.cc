#include "TemporaryQueueWriter.h"

void TemporaryQueueWriter::Run() {
    _testimony_queue_writer();
}

void TemporaryQueueWriter::OnWaitForStop(){

}

void TemporaryQueueWriter::Stop() {
	//SignalStop();
	//WaitForStop();
}

void TemporaryQueueWriter::StartThread() {
    Start();
}
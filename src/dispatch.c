#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "analysis.h"


#define TASK_QUEUE_SIZE 20


Task taskQueue[TASK_QUEUE_SIZE]; //creates task queue array
int taskCount = 0; // int to store the number of tasks

int front = 0; //index of the front of the queue
int rear = -1; //index of the rear of the queue


int terminate = 0; // flag for when the threads should terminate


pthread_mutex_t mutexQueue; //declare the mutex and condition variables
pthread_cond_t condQueue;

// assigns a task to a thread and processes it
void* startThread(void* args){
    while(1){
        Task task;

        pthread_mutex_lock(&mutexQueue);

        while(taskCount == 0 && !terminate){
            pthread_cond_wait(&condQueue, &mutexQueue);
        }
        //if there are no more tasks and terminate flag is 1
        if(terminate && taskCount == 0){
            pthread_mutex_unlock(&mutexQueue); //exits
            break;
        }

        //get the first task in the queue
        task = taskQueue[front];
        front = (front + 1) % TASK_QUEUE_SIZE;
        // reduce task count as one will be processed
        taskCount--;
        pthread_cond_signal(&condQueue);
        pthread_mutex_unlock(&mutexQueue);

        //process the task
        analyse(task.header, task.packet, task.verbose);

        //free up the memory for the copy of packet and header as task has been completed now
        free((void *)task.packet);
        free(task.header);
    }
    return NULL;
}

// adds a task to the task queue so that it can be processed later
void submitTask(Task task){
    pthread_mutex_lock(&mutexQueue);
    // if the there are too many tasks in the task queue, then wait until its not
    if(taskCount >= TASK_QUEUE_SIZE){
        pthread_cond_wait(&condQueue, &mutexQueue);
    }

    // once there is space, then enqueue the new task and incrmement the counter
    rear = (rear + 1) % TASK_QUEUE_SIZE;
    taskQueue[rear] = task;
    taskCount++;
    pthread_mutex_unlock(&mutexQueue);
    pthread_cond_signal(&condQueue);
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
    struct pcap_pkthdr *headerCopy = malloc(sizeof(struct pcap_pkthdr));
    // creates cop of header as to not have memory overwrite concerns, does the same with packet
    // if error then exit
    if(!headerCopy){
        exit(EXIT_FAILURE);
    }
    memcpy(headerCopy, header, sizeof(struct pcap_pkthdr));

    unsigned char *packetCopy = malloc(header->caplen);
    // similar to above except must free variable that you just got
    if(!packetCopy){
        free(headerCopy);
        exit(EXIT_FAILURE);
    }
    memcpy(packetCopy, packet, header->caplen);

    // creates a new task object and submits it
    Task task = {headerCopy, packetCopy, verbose};
    submitTask(task);
}


